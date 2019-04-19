package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/pflag"
)

const (
	headerPrestoClientTags = "X-Presto-Client-Tags"
)

func handleBackground(rep *Response) {
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

		// Fetch the next state.
		resp, err := http.Get(nextUri)
		if err != nil {
			log.Printf("%s: error fetching next state: %s: %s", id, nextUri, err)
			return
		}

		// Retry..
		if resp.StatusCode == 503 {
			log.Printf("%s: error fetching next state: %s: %s... retrying", id, nextUri, resp.Status)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		if resp.StatusCode != 200 && resp.Header.Get("content-type") != "application/json" {
			log.Printf("%s: error fetching next state: %s: %s", id, nextUri, resp.Status)
			return
		}

		// Decode body to get next response.
		rep = &Response{}
		if err := json.NewDecoder(resp.Body).Decode(rep); err != nil {
			resp.Body.Close()
			log.Printf("%s: error decoding response: %s: %s", id, nextUri, err)
			return
		}
		resp.Body.Close()

		time.Sleep(500 * time.Millisecond)
	}
}

func main() {
	var (
		bindAddr string
		server   string
	)

	pflag.StringVar(&bindAddr, "bind.addr", "localhost:8081", "Presto proxy bind address.")
	pflag.StringVar(&server, "server", "localhost:8080", "Presto server location")

	pflag.Parse()

	if !strings.HasPrefix(server, "http://") || !strings.HasPrefix(server, "https://") {
		server = "http://" + server
	}

	pserver, err := url.Parse(server)
	if err != nil {
		log.Fatal(err)
	}

	proxy := httputil.NewSingleHostReverseProxy(pserver)

	proxy.ModifyResponse = func(r *http.Response) error {
		// Not a request to schedule a query.
		if r.Request.URL.Path != "/v1/statement" || r.Request.Method != "POST" {
			return nil
		}

		// Check for async client tag.
		var async bool
		for _, tag := range r.Request.Header[headerPrestoClientTags] {
			tag = strings.ToLower(tag)
			if tag == "async=true" || tag == "async=1" {
				async = true
				break
			}
		}

		// Not an async request, pass through.
		if !async {
			return nil
		}

		// Read body response body which contains the QUEUED query state.
		var rep Response
		err := json.NewDecoder(r.Body).Decode(&rep)
		r.Body.Close()
		if err != nil {
			return err
		}

		go handleBackground(&rep)

		nrep := &Response{
			Id:      rep.Id,
			InfoUri: rep.InfoUri,
			Columns: []*Column{
				{
					Name: "id",
					Type: fmt.Sprintf("varchar(%d)", len(rep.Id)),
					TypeSignature: TypeSignature{
						RawType: "varchar",
						Arguments: []interface{}{
							map[string]interface{}{
								"kind":  "LONG_LITERAL",
								"value": len(rep.Id),
							},
						},
					},
				},
				{
					Name: "info_uri",
					Type: fmt.Sprintf("varchar(%d)", len(rep.InfoUri)),
					TypeSignature: TypeSignature{
						RawType: "varchar",
						Arguments: []interface{}{
							map[string]interface{}{
								"kind":  "LONG_LITERAL",
								"value": len(rep.InfoUri),
							},
						},
					},
				},
			},
			Data: [][]interface{}{
				{
					rep.Id,
					rep.InfoUri,
				},
			},
			Stats: &Stats{
				State:              "FINISHED",
				Queued:             false,
				Scheduled:          true,
				ProgressPercentage: 100,
			},
			Warnings:                      []interface{}{},
			AddedPreparedStatements:       struct{}{},
			DeallocatedPreparedStatements: []interface{}{},
		}

		// Marshal new response body and Update content-length header.
		b, _ := json.Marshal(nrep)
		r.Header.Set("content-length", fmt.Sprint(len(b)))
		r.Body = ioutil.NopCloser(bytes.NewBuffer(b))
		return nil
	}

	if err := http.ListenAndServe(bindAddr, proxy); err != nil {
		log.Fatal(err)
	}
}
