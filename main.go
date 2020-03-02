package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/arcus/pkg/config"
	"github.com/arcus/pkg/log"
	"github.com/spf13/pflag"
)

const (
	headerPrestoUser       = "X-Presto-User"
	headerPrestoClientTags = "X-Presto-Client-Tags"
)

func main() {
	if err := run(); err != nil {
		log.New(os.Stdout).Info(err)
	}
}

func run() error {
	var cfg Config

	config.Init("PRESTO_PROXY", &cfg, func(fs *pflag.FlagSet) error {
		fs.String("http.bind", "localhost:8081", "Presto proxy bind address.")
		fs.String("http.advertise", "", "Presto proxy advertise address.")
		fs.String("http.tls.crt", "", "TLS cert path.")
		fs.String("http.tls.key", "", "TLS key path.")
		fs.String("presto.addr", "localhost:8080", "Presto server location")
		fs.String("ldap.addr", "", "LDAP server address.")

		return nil
	})

	logger := log.New(os.Stdout)

	if !strings.HasPrefix(cfg.Presto.Addr, "http://") && !strings.HasPrefix(cfg.Presto.Addr, "https://") {
		cfg.Presto.Addr = "http://" + cfg.Presto.Addr
	}

	targetAddr, err := url.Parse(cfg.Presto.Addr)
	if err != nil {
		return err
	}

	if cfg.HTTP.Advertise == "" {
		cfg.HTTP.Advertise = cfg.HTTP.Bind
	}

	if !strings.HasPrefix(cfg.HTTP.Advertise, "http://") && !strings.HasPrefix(cfg.HTTP.Advertise, "https://") {
		cfg.HTTP.Advertise = "http://" + cfg.HTTP.Advertise
	}

	advertiseAddr, err := url.Parse(cfg.HTTP.Advertise)
	if err != nil {
		return err
	}

	if cfg.HTTP.TLS.Key != "" {
		advertiseAddr.Scheme = "https"
	}

	var authBackend *ldapBackend
	if cfg.LDAP.Addr != "" {
		// Configure LDAP connection.
		authBackend = &ldapBackend{
			Address: cfg.LDAP.Addr,
		}

		// Ensure a connection can be established.
		if err := authBackend.Ping(); err != nil {
			return err
		}
	}

	logger.Info(
		"proxy configured",
		"listen_addr", cfg.HTTP.Bind,
		"proxy_addr", targetAddr.String(),
		"advertised_addr", advertiseAddr.String(),
	)

	// Function to rewrite a URL to use the proxy scheme and host.
	rewriteURL := func(u string) string {
		if u == "" {
			return ""
		}
		p, _ := url.Parse(u)
		p.Scheme = advertiseAddr.Scheme
		p.Host = advertiseAddr.Host
		return p.String()
	}

	// Setup reverse proxy.
	proxy := httputil.NewSingleHostReverseProxy(targetAddr)

	proxy.ModifyResponse = func(r *http.Response) error {
		// Ignore responses with empty bodies.
		if r.ContentLength <= 0 {
			logger.Info("ignoring no content")
			return nil
		}

		// Ignore non-JSON payloads (although this should not occur).
		if r.Header.Get("content-type") != "application/json" {
			logger.Debug("ignoring unknown content-type")
			return nil
		}

		// Ignore gzipped payloads.
		if r.Header.Get("content-encoding") != "" {
			logger.Debug("ignoring unknown content-encoding")
			return nil
		}

		body, err := ioutil.ReadAll(r.Body)
		r.Body.Close()
		if err != nil {
			return fmt.Errorf("failed to read body: %s", err)
		}

		// Decode the response body from Presto in order to rewrite the URLs
		// and possibly handle the response polling in the background.
		rep := &Response{}
		err = json.Unmarshal(body, rep)
		if err != nil {
			logger.Debug("failed to decoded response body",
				"error", err,
			)
			r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
			return nil
		}

		// Rewrite URLs to be relative to the proxy.
		rep.InfoUri = rewriteURL(rep.InfoUri)
		rep.NextUri = rewriteURL(rep.NextUri)

		// Check for POST for new queries.
		if r.Request.Method == "POST" && r.Request.URL.Path == "/v1/statement" {
			// Check for async client tag.
			var async bool
			for _, tag := range r.Request.Header[headerPrestoClientTags] {
				tag = strings.ToLower(tag)
				if tag == "async=1" {
					async = true
					break
				}
			}

			// Handle query in the background and change the response to include the URL.
			if async {
				logger.Info(
					"handled async query",
					"query_id", rep.Id,
					"info_uri", rep.InfoUri,
				)
				go handleBackground(logger, rep, targetAddr)
				rep = newAsyncResponse(rep.Id, rep.InfoUri)
			}
		}

		// Marshal new response body and Update content-length header.
		b, _ := json.Marshal(rep)
		r.Header.Set("content-length", fmt.Sprint(len(b)))
		r.Body = ioutil.NopCloser(bytes.NewBuffer(b))
		logger.Info("updated proxied response body")
		return nil
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Authenticate POST requests.
		if authBackend != nil && r.Method == "POST" {
			t0 := time.Now()
			if checkAuthorization(authBackend, w, r) {
				logger.Info("authorization failed",
					"latency_ms", time.Since(t0)/time.Millisecond,
				)
				return
			}
			logger.Info("authorization succeeded",
				"latency_ms", time.Since(t0)/time.Millisecond,
			)
		}

		// Remove the authorization header prior to proxying.
		r.Header.Del("Authorization")
		proxy.ServeHTTP(w, r)
	})

	// Serve HTTP.
	if cfg.HTTP.TLS.Crt != "" {
		return http.ListenAndServeTLS(cfg.HTTP.Bind, cfg.HTTP.TLS.Crt, cfg.HTTP.TLS.Key, nil)
	}

	return http.ListenAndServe(cfg.HTTP.Bind, nil)
}

func checkAuthorization(authBackend *ldapBackend, w http.ResponseWriter, r *http.Request) bool {
	// Authorization header required.
	header := r.Header.Get("Authorization")
	if header == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}

	// Malformed authorization value.
	splitIdx := strings.IndexByte(header, ' ')
	if splitIdx == -1 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Bad authorization header")
		return true
	}

	// Auth method and base64 encoded creds.
	method, ecreds := header[:splitIdx], header[splitIdx+1:]

	if method != "Basic" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintln(w, "Basic auth required")
		return true
	}

	// Decode creds (as a byte slice)
	creds, err := base64.StdEncoding.DecodeString(ecreds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Invalid Basic auth encoding")
		return true
	}

	// Split creds by colon.
	splitIdx = bytes.IndexByte(creds, ':')
	if splitIdx == -1 {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Password required")
		return true
	}

	// Prepare username and password and authenticate client.
	username, password := string(creds[:splitIdx]), string(creds[splitIdx+1:])
	username = strings.TrimSpace(username)
	password = strings.TrimSpace(password)

	if username == "" || password == "" {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "Username and password required")
		return true
	}

	ok, err := authBackend.Authenticate(r.Context(), username, password)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(w, "LDAP server error: %s", err)
		return true
	}
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}

	// Set the presto user so its reflected in the UI and logged as the requesting user.
	r.Header.Set(headerPrestoUser, username)
	return false
}

func handleBackground(logger log.Logger, rep *Response, targetAddr *url.URL) {
	rewriteURL := func(u string) string {
		if u == "" {
			return ""
		}
		p, _ := url.Parse(u)
		p.Scheme = targetAddr.Scheme
		p.Host = targetAddr.Host
		return p.String()
	}

	id := rep.Id
	state := rep.Stats.State

	stateTime := time.Now()
	logger.Info("query state change",
		"query_id", id,
		"state", state,
	)

	// Keep track of the observed states.
	observedStates := map[string]struct{}{
		state: struct{}{},
	}

	for {
		state = rep.Stats.State

		// Log only new state transitions since some queries may take hours.
		if _, ok := observedStates[state]; !ok {
			observedStates[state] = struct{}{}
			nextTime := time.Now()
			logger.Info("query state change",
				"query_id", id,
				"state", state,
				"transition_ms", nextTime.Sub(stateTime)/time.Millisecond,
			)
			stateTime = nextTime
		}

		if state == "FAILED" {
			logger.Info("query state change",
				"query_id", id,
				"state", state,
				"error", rep.Error.Message,
			)
		}

		nextURI := rep.NextUri
		if nextURI == "" {
			return
		}

		// The URL host will be set to the proxy address. Rewrite to the Presto
		// server address so the requests are direct.
		nextURI = rewriteURL(nextURI)

		// Fetch the next state.
		hrep, err := http.Get(nextURI)
		if err != nil {
			logger.Info("error fetching next state",
				"query_id", id,
				"state", state,
				"error", err,
				"next_uri", nextURI,
			)
			return
		}

		// Retry.. if the service is unavailable.
		if hrep.StatusCode == 503 {
			logger.Info("error fetching next state",
				"query_id", id,
				"state", state,
				"http_status", hrep.Status,
				"next_uri", nextURI,
			)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if hrep.StatusCode != 200 && hrep.Header.Get("content-type") != "application/json" {
			logger.Info("error fetching next state",
				"query_id", id,
				"state", state,
				"http_status", hrep.Status,
				"next_uri", nextURI,
			)
			return
		}

		// Decode body to get next response.
		rep = &Response{}
		dec := json.NewDecoder(hrep.Body)
		err = dec.Decode(rep)
		hrep.Body.Close()
		if err != nil {
			logger.Info("error decoding response",
				"query_id", id,
				"state", state,
				"error", err,
				"next_uri", nextURI,
			)
			return
		}

		// Delay in between requests.
		time.Sleep(500 * time.Millisecond)
	}
}
