package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/arcus/pkg/config"
	"github.com/spf13/pflag"
)

const (
	headerPrestoUser       = "X-Presto-User"
	headerPrestoClientTags = "X-Presto-Client-Tags"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
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
		fs.String("ldap.username", "", "LDAP username.")
		fs.String("ldap.password", "", "LDAP password.")
		fs.String("ldap.searchdn", "", "LDAP search DN.")
		fs.String("ldap.searchfilter", "", "LDAP search filter.")

		return nil
	})

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
			Address:      cfg.LDAP.Addr,
			Username:     cfg.LDAP.Username,
			Password:     cfg.LDAP.Password,
			SearchDN:     cfg.LDAP.SearchDN,
			SearchFilter: cfg.LDAP.SearchFilter,
		}

		// Ensure a connection can be established.
		if err := authBackend.Ping(); err != nil {
			return err
		}
	}

	log.Printf("listening on: %s", cfg.HTTP.Bind)
	log.Printf("proxying to: %s", targetAddr)
	log.Printf("advertised as: %s", advertiseAddr)

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
		log.Printf("received %s %s", r.Request.Method, r.Request.URL)

		// Ignore responses with empty bodies.
		if r.ContentLength <= 0 {
			return nil
		}

		// Ignore non-JSON payloads (although this should not occur).
		if r.Header.Get("content-type") != "application/json" {
			return nil
		}

		// Ignore gzipped payloads.
		if r.Header.Get("content-encoding") != "" {
			return nil
		}

		// Decode the response body from Presto in order to rewrite the URLs
		// and possibly handle the response polling in the background.
		rep := &Response{}
		dec := json.NewDecoder(r.Body)
		err := dec.Decode(rep)
		r.Body.Close()
		if err != nil {
			log.Printf("%s %s %s", r.Request.Method, r.Request.URL, r.Header)
			return fmt.Errorf("error decoding response body: %s", err)
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
				go handleBackground(rep, targetAddr)
				rep = newAsyncResponse(rep.Id, rep.InfoUri)
			}
		}

		// Marshal new response body and Update content-length header.
		b, _ := json.Marshal(rep)
		r.Header.Set("content-length", fmt.Sprint(len(b)))
		r.Body = ioutil.NopCloser(bytes.NewBuffer(b))
		return nil
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Authenticate POST requests.
		if authBackend != nil && r.Method == "POST" {
			// Authorization header required.
			header := r.Header.Get("Authorization")
			if header == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Malformed authorization value.
			splitIdx := strings.IndexByte(header, ' ')
			if splitIdx == -1 {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintln(w, "Bad authorization header")
				return
			}

			// Auth method and base64 encoded creds.
			method, ecreds := header[:splitIdx], header[splitIdx+1:]

			if method != "Basic" {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintln(w, "Basic auth required")
				return
			}

			// Decode creds (as a byte slice)
			creds, err := base64.StdEncoding.DecodeString(ecreds)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintln(w, "Invalid Basic auth encoding")
				return
			}

			// Split creds by colon.
			splitIdx = bytes.IndexByte(creds, ':')
			if splitIdx == -1 {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprintln(w, "Password required")
				return
			}

			// Prepare username and password and authenticate client.
			username, password := string(creds[:splitIdx]), string(creds[splitIdx+1:])
			ok, err := authBackend.Authenticate(r.Context(), username, password)
			if err != nil {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprintf(w, "LDAP server error: %s", err)
				return
			}
			if !ok {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Set the presto user so its reflected in the UI and logged as the requesting user.
			r.Header.Set(headerPrestoUser, username)
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

func handleBackground(rep *Response, targetAddr *url.URL) {
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
	log.Printf("%s: state=%s", id, state)

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
			log.Printf("%s: state=%s transition=%s", id, state, nextTime.Sub(stateTime))
			stateTime = nextTime
		}

		if state == "FAILED" {
			log.Printf("%s: %s", id, rep.Error.Message)
		}

		nextUri := rep.NextUri
		if nextUri == "" {
			return
		}

		// The URL host will be set to the proxy address. Rewrite to the Presto
		// server address so the requests are direct.
		nextUri = rewriteURL(nextUri)

		// Fetch the next state.
		hrep, err := http.Get(nextUri)
		if err != nil {
			log.Printf("%s: error fetching next state: %s: %s", id, nextUri, err)
			return
		}

		// Retry.. if the service is unavailable.
		if hrep.StatusCode == 503 {
			log.Printf("%s: error fetching next state: %s: %s... retrying", id, nextUri, hrep.Status)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if hrep.StatusCode != 200 && hrep.Header.Get("content-type") != "application/json" {
			log.Printf("%s: error fetching next state: %s: %s", id, nextUri, hrep.Status)
			return
		}

		// Decode body to get next response.
		rep = &Response{}
		dec := json.NewDecoder(hrep.Body)
		err = dec.Decode(rep)
		hrep.Body.Close()
		if err != nil {
			log.Printf("%s: error decoding response: %s: %s", id, nextUri, err)
			return
		}

		// Delay in between requests.
		time.Sleep(500 * time.Millisecond)
	}
}
