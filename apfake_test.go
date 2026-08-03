// Copyright 2025 Vadim Filin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeInstance is an in-process Fediverse server: a TLS httptest instance that
// answers the ActivityPub and Mastodon-REST endpoints the gateway dereferences,
// records what was fetched, and captures signed inbox deliveries. It keeps the
// federation tests hermetic — no test ever leaves the process.
type fakeInstance struct {
	srv *httptest.Server

	mu       sync.Mutex
	handlers map[string]http.HandlerFunc
	hits     map[string]int
	posts    []delivery
}

// delivery is one activity a peer inbox received.
type delivery struct {
	path string
	doc  map[string]any
	sig  string
}

func newFakeInstance(t *testing.T) *fakeInstance {
	t.Helper()
	f := &fakeInstance{handlers: map[string]http.HandlerFunc{}, hits: map[string]int{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeInstance) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits[r.URL.Path]++
	h, ok := f.handlers[r.URL.Path]
	f.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	h(w, r)
}

// attach points the gateway's outbound client at this instance's TLS cert.
func (f *fakeInstance) attach(g *gateway) *fakeInstance {
	g.client = f.srv.Client()
	return f
}

func (f *fakeInstance) url(path string) string { return f.srv.URL + path }
func (f *fakeInstance) host() string           { return strings.TrimPrefix(f.srv.URL, "https://") }

func (f *fakeInstance) on(path string, h http.HandlerFunc) *fakeInstance {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handlers[path] = h
	return f
}

// serveDoc answers path with v encoded as JSON under contentType.
func (f *fakeInstance) serveDoc(path, contentType string, v any) *fakeInstance {
	return f.on(path, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, contentType, v)
	})
}

func (f *fakeInstance) hitCount(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

// inbox registers path as an inbox that accepts and records deliveries.
func (f *fakeInstance) inbox(path string) *fakeInstance {
	return f.on(path, func(w http.ResponseWriter, r *http.Request) {
		var doc map[string]any
		_ = json.NewDecoder(r.Body).Decode(&doc)
		f.mu.Lock()
		f.posts = append(f.posts, delivery{path: r.URL.Path, doc: doc, sig: r.Header.Get("Signature")})
		f.mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	})
}

func (f *fakeInstance) delivered() []delivery {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]delivery, len(f.posts))
	copy(out, f.posts)
	return out
}

// actor registers a minimal actor document at /users/{name} plus its inbox, and
// returns the actor URL. pub, when non-nil, is published as the actor's signing
// key so a signature made with it verifies against this document.
func (f *fakeInstance) actor(name string, pub *rsa.PublicKey) string {
	id := f.url("/users/" + name)
	doc := map[string]any{
		"@context":          []any{asContext, secContext},
		"id":                id,
		"type":              "Person",
		"preferredUsername": name,
		"inbox":             id + pathInbox,
		"outbox":            id + "/outbox",
		"followers":         id + pathFollowers,
		"following":         id + "/following",
	}
	if pub != nil {
		pem, err := publicKeyPEM(&rsa.PrivateKey{PublicKey: *pub})
		if err == nil {
			doc["publicKey"] = map[string]any{
				"id": id + "#main-key", "owner": id, "publicKeyPem": pem,
			}
		}
	}
	f.serveDoc("/users/"+name, contentTypeAP, doc)
	f.inbox("/users/" + name + pathInbox)
	return id
}

// webfingerFor makes handle "{name}@{host}" resolvable to the given actor URL.
func (f *fakeInstance) webfingerFor(name, actorURL string) *fakeInstance {
	return f.on("/.well-known/webfinger", func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("resource"), name) {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, contentTypeJRD, webFingerJRD{
			Subject: "acct:" + name + "@" + f.host(),
			Links:   []webFingerLink{{Rel: "self", Type: contentTypeAP, Href: actorURL}},
		})
	})
}

// apNote is a minimal ActivityPub Note document.
func apNote(id, author, content string) map[string]any {
	return map[string]any{
		"type": typeNote, "id": id, "attributedTo": author,
		"content": content, "published": "2024-01-01T00:00:00Z",
	}
}
