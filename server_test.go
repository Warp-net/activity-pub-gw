// Copyright 2025 Vadim Filin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
)

// getJSON fetches path off srv and decodes the body into v.
func getJSON(t *testing.T, srv *httptest.Server, path string, v any) *http.Response {
	t.Helper()
	resp, err := http.Get(srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if v != nil {
		if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	return resp
}

func TestHandleInstanceActor(t *testing.T) {
	g := testGateway(t)
	srv := httptest.NewServer(g.routes())
	defer srv.Close()

	var a actor
	resp := getJSON(t, srv, pathActor, &a)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get(headerContentType); ct != contentTypeAP {
		t.Fatalf("content-type = %q", ct)
	}
	// Peers re-fetch the instance actor to verify every signed request; without a
	// cache hint that becomes a fetch storm against /actor.
	if cc := resp.Header.Get("Cache-Control"); cc != "max-age=3600" {
		t.Fatalf("cache-control = %q", cc)
	}
	if a.Type != "Application" || a.PreferredUsername != instanceActorName {
		t.Fatalf("actor = %+v", a)
	}
	if a.ID != g.instanceActorID() || a.PublicKey.ID != g.instanceKeyID() {
		t.Fatalf("ids: %q / %q", a.ID, a.PublicKey.ID)
	}
	if !strings.Contains(a.PublicKey.PublicKeyPEM, "BEGIN PUBLIC KEY") {
		t.Fatal("the instance actor must publish the gateway signing key")
	}
	if a.Endpoints == nil || a.Endpoints.SharedInbox != g.baseURL()+pathInbox {
		t.Fatalf("endpoints = %+v", a.Endpoints)
	}
}

// The keyId actor must be webfinger-resolvable or peers re-resolve it on every
// signed request.
func TestWebFingerResolvesTheInstanceActor(t *testing.T) {
	g := testGateway(t)
	srv := httptest.NewServer(g.routes())
	defer srv.Close()

	var jrd webFingerJRD
	resp := getJSON(t, srv, "/.well-known/webfinger?resource=acct:"+instanceActorName+"@gw.example", &jrd)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(jrd.Links) != 1 || jrd.Links[0].Href != g.instanceActorID() {
		t.Fatalf("jrd = %+v", jrd)
	}
}

func TestWebFingerRejectsBadResources(t *testing.T) {
	srv := httptest.NewServer(testGateway(t).routes())
	defer srv.Close()

	cases := map[string]int{
		"/.well-known/webfinger?resource=alice":           http.StatusBadRequest, // no @
		"/.well-known/webfinger":                          http.StatusBadRequest,
		"/.well-known/webfinger?resource=acct:alice@else": http.StatusNotFound, // another domain
	}
	for path, want := range cases {
		resp := getJSON(t, srv, path, nil)
		if resp.StatusCode != want {
			t.Errorf("%s = %d, want %d", path, resp.StatusCode, want)
		}
	}
}

func TestHandleInstanceActorSub(t *testing.T) {
	g := testGateway(t)
	srv := httptest.NewServer(g.routes())
	defer srv.Close()

	for _, sub := range []string{"outbox", "followers", "following"} {
		var col orderedCollection
		resp := getJSON(t, srv, pathActor+"/"+sub, &col)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d", sub, resp.StatusCode)
		}
		if col.Type != "OrderedCollection" || col.TotalItems != 0 || len(col.OrderedItems) != 0 {
			t.Fatalf("%s = %+v, want an empty collection", sub, col)
		}
		if col.ID != g.baseURL()+pathActor+"/"+sub {
			t.Fatalf("%s id = %q", sub, col.ID)
		}
	}

	if resp := getJSON(t, srv, pathActor+"/nope", nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown sub-collection = %d, want 404", resp.StatusCode)
	}
}

func TestHandleUsersDispatch(t *testing.T) {
	g := testGateway(t)
	srv := httptest.NewServer(g.routes())
	defer srv.Close()

	cases := map[string]int{
		"/users/alice":            http.StatusOK,
		"/users/alice/":           http.StatusOK, // trailing slash is the actor too
		"/users/alice/outbox":     http.StatusOK,
		"/users/alice/followers":  http.StatusOK,
		"/users/alice/following":  http.StatusOK,
		"/users/bob":              http.StatusNotFound, // unknown user
		"/users/alice/nope":       http.StatusNotFound,
		"/users/alice/statuses":   http.StatusNotFound, // no status id
		"/users/alice/statuses/":  http.StatusNotFound,
		"/users/alice/statuses/1": http.StatusNotFound, // no node wired
		"/users/alice/inbox":      http.StatusMethodNotAllowed,
	}
	for path, want := range cases {
		resp := getJSON(t, srv, path, nil)
		if resp.StatusCode != want {
			t.Errorf("GET %s = %d, want %d", path, resp.StatusCode, want)
		}
	}
}

func TestServeFollowers(t *testing.T) {
	g := testGateway(t)
	if err := g.followers.Add("alice", "https://m.example/users/bob"); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(g.routes())
	defer srv.Close()

	var col orderedCollection
	getJSON(t, srv, "/users/alice/followers", &col)
	if col.TotalItems != 1 || len(col.OrderedItems) != 1 {
		t.Fatalf("collection = %+v", col)
	}
	if col.OrderedItems[0] != "https://m.example/users/bob" {
		t.Fatalf("item = %v", col.OrderedItems[0])
	}
	if col.ID != g.actorID("alice")+pathFollowers {
		t.Fatalf("id = %q", col.ID)
	}
}

// errFollowerStore fails every read, standing in for an unreachable owner node.
type errFollowerStore struct{ err error }

func (e errFollowerStore) Add(string, string) error      { return e.err }
func (e errFollowerStore) List(string) ([]string, error) { return nil, e.err }

func TestServeFollowersToleratesAStoreError(t *testing.T) {
	g := testGateway(t)
	g.followers = errFollowerStore{err: errors.New("node down")}
	w := httptest.NewRecorder()
	g.serveFollowers(w, "alice")

	var col orderedCollection
	if err := json.Unmarshal(w.Body.Bytes(), &col); err != nil {
		t.Fatal(err)
	}
	if col.TotalItems != 0 || col.OrderedItems == nil {
		t.Fatalf("collection = %+v, want an empty (never null) list", col)
	}
}

func TestServeOutbox(t *testing.T) {
	parent := "01PARENT0000000000000000000"
	by := "bob@m"
	tweets := []tweet{
		{Id: "t1", UserId: "alice", CreatedAt: time.Unix(0, 0)},                    // publishable
		{Id: "t2", UserId: "alice", ParentId: &parent, CreatedAt: time.Unix(0, 0)}, // reply: filtered
		{Id: "t3", UserId: "alice", RetweetedBy: &by, CreatedAt: time.Unix(0, 0)},  // boost: filtered
		{Id: "t4", UserId: "carol", CreatedAt: time.Unix(0, 0)},                    // someone else's
	}

	t.Run("inlines only original top-level posts", func(t *testing.T) {
		g := testGateway(t)
		bt, _ := json.Marshal(tweetsResponse{Tweets: tweets})
		g.req = &fakeRequester{tweetsJSON: bt}

		w := httptest.NewRecorder()
		g.serveOutbox(w, "alice")
		var col orderedCollection
		if err := json.Unmarshal(w.Body.Bytes(), &col); err != nil {
			t.Fatal(err)
		}
		// totalItems must match what is actually served, or Mastodon shows
		// "Posts: N" over a short tab.
		if col.TotalItems != 1 || len(col.OrderedItems) != 1 {
			t.Fatalf("collection = %d items / totalItems %d, want 1", len(col.OrderedItems), col.TotalItems)
		}
		item, _ := json.Marshal(col.OrderedItems[0])
		var act activity
		if err := json.Unmarshal(item, &act); err != nil {
			t.Fatal(err)
		}
		if act.Type != typeCreate || act.Actor != g.actorID("alice") {
			t.Fatalf("item = %+v, want a Create by alice", act)
		}
	})

	t.Run("no node serves an empty collection", func(t *testing.T) {
		g := testGateway(t)
		w := httptest.NewRecorder()
		g.serveOutbox(w, "alice")
		var col orderedCollection
		if err := json.Unmarshal(w.Body.Bytes(), &col); err != nil {
			t.Fatal(err)
		}
		if col.TotalItems != 0 || col.ID != g.actorID("alice")+"/outbox" {
			t.Fatalf("collection = %+v", col)
		}
	})

	t.Run("a node error serves an empty collection", func(t *testing.T) {
		g := testGateway(t)
		g.req = errRequester{err: errors.New("unreachable")}
		w := httptest.NewRecorder()
		g.serveOutbox(w, "alice")
		var col orderedCollection
		if err := json.Unmarshal(w.Body.Bytes(), &col); err != nil {
			t.Fatal(err)
		}
		if col.TotalItems != 0 {
			t.Fatalf("collection = %+v", col)
		}
	})

	t.Run("a malformed node response serves an empty collection", func(t *testing.T) {
		g := testGateway(t)
		g.req = rawRequester{body: []byte("not json")}
		w := httptest.NewRecorder()
		g.serveOutbox(w, "alice")
		var col orderedCollection
		if err := json.Unmarshal(w.Body.Bytes(), &col); err != nil {
			t.Fatal(err)
		}
		if col.TotalItems != 0 {
			t.Fatalf("collection = %+v", col)
		}
	})
}

func TestServeFollowing(t *testing.T) {
	t.Run("warpnet follows resolve locally, fediverse follows to their actor url", func(t *testing.T) {
		g := testGateway(t)
		g.actorIDs = expirable.NewLRU[string, string](actorIDsSize, nil, actorIDsTTL)
		g.actorIDs.Add("bob@m.example", "https://m.example/users/bob")
		bt, _ := json.Marshal(followingsResponse{Followings: []string{
			"01KSGHBHKG0N77T6A3RZV8WSH5", // native warpnet user
			"bob@m.example",              // bridged handle, resolved via the cache
			"@",                          // unresolvable id: skipped, not fatal
		}})
		g.req = &fakeRequester{followingsJSON: bt}

		w := httptest.NewRecorder()
		g.serveFollowing(w, "alice")
		var col orderedCollection
		if err := json.Unmarshal(w.Body.Bytes(), &col); err != nil {
			t.Fatal(err)
		}
		if col.TotalItems != 2 {
			t.Fatalf("items = %v, want the native and the resolvable bridged follow", col.OrderedItems)
		}
		if col.OrderedItems[0] != g.actorID("01KSGHBHKG0N77T6A3RZV8WSH5") {
			t.Fatalf("native follow = %v, want our own actor url", col.OrderedItems[0])
		}
		if col.OrderedItems[1] != "https://m.example/users/bob" {
			t.Fatalf("bridged follow = %v", col.OrderedItems[1])
		}
	})

	t.Run("no node, node error and bad json all serve an empty collection", func(t *testing.T) {
		for name, g := range map[string]*gateway{
			"no node":  testGateway(t),
			"error":    testGateway(t),
			"bad json": testGateway(t),
		} {
			switch name {
			case "error":
				g.req = errRequester{err: errors.New("x")}
			case "bad json":
				g.req = rawRequester{body: []byte("{{{")}
			}
			w := httptest.NewRecorder()
			g.serveFollowing(w, "alice")
			var col orderedCollection
			if err := json.Unmarshal(w.Body.Bytes(), &col); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if col.TotalItems != 0 {
				t.Fatalf("%s: collection = %+v", name, col)
			}
		}
	})
}

func TestServeRepliesWithoutANode(t *testing.T) {
	g := testGateway(t)
	w := httptest.NewRecorder()
	g.serveReplies(w, "alice", "t1")
	var col orderedCollection
	if err := json.Unmarshal(w.Body.Bytes(), &col); err != nil {
		t.Fatal(err)
	}
	if col.TotalItems != 0 || col.ID != g.actorID("alice")+pathStatuses+"t1/replies" {
		t.Fatalf("collection = %+v", col)
	}

	t.Run("a node error serves empty", func(t *testing.T) {
		g := testGateway(t)
		g.req = errRequester{err: errors.New("x")}
		w := httptest.NewRecorder()
		g.serveReplies(w, "alice", "t1")
		var col orderedCollection
		if err := json.Unmarshal(w.Body.Bytes(), &col); err != nil {
			t.Fatal(err)
		}
		if col.TotalItems != 0 {
			t.Fatalf("collection = %+v", col)
		}
	})

	t.Run("bad json serves empty", func(t *testing.T) {
		g := testGateway(t)
		g.req = rawRequester{body: []byte("nope")}
		w := httptest.NewRecorder()
		g.serveReplies(w, "alice", "t1")
		var col orderedCollection
		if err := json.Unmarshal(w.Body.Bytes(), &col); err != nil {
			t.Fatal(err)
		}
		if col.TotalItems != 0 {
			t.Fatalf("collection = %+v", col)
		}
	})
}

func TestNodeInfo(t *testing.T) {
	g := testGateway(t)
	srv := httptest.NewServer(g.routes())
	defer srv.Close()

	var links nodeInfoLinks
	getJSON(t, srv, "/.well-known/nodeinfo", &links)
	if len(links.Links) != 1 || links.Links[0].Href != g.baseURL()+"/nodeinfo/2.0" {
		t.Fatalf("links = %+v", links)
	}

	var info map[string]any
	getJSON(t, srv, "/nodeinfo/2.0", &info)
	if info["version"] != "2.0" {
		t.Fatalf("version = %v", info["version"])
	}
	sw, _ := info["software"].(map[string]any)
	if sw["name"] != "warpnet-fediverse-gateway" || sw["version"] != gatewayVersion {
		t.Fatalf("software = %+v", sw)
	}
	if info["openRegistrations"] != false {
		t.Fatalf("openRegistrations = %v", info["openRegistrations"])
	}
}

func TestWriteJSONReportsUnmarshalableValues(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, contentTypeAP, math.Inf(1)) // JSON cannot represent Inf
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestLogRequestsRecordsTheStatus(t *testing.T) {
	h := logRequests(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusGone)
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w.Code != http.StatusGone {
		t.Fatalf("status = %d, want the wrapper to pass it through", w.Code)
	}

	// A handler that never calls WriteHeader is logged as 200.
	sw := &statusWriter{ResponseWriter: httptest.NewRecorder(), status: http.StatusOK}
	if sw.status != http.StatusOK {
		t.Fatalf("default status = %d", sw.status)
	}
	sw.WriteHeader(http.StatusTeapot)
	if sw.status != http.StatusTeapot {
		t.Fatalf("status = %d", sw.status)
	}
}

func TestUserFromActorURL(t *testing.T) {
	cases := map[string]string{
		"https://gw.example/users/alice":            "alice",
		"https://gw.example/users/alice/statuses/1": "alice",
		"https://gw.example/users/alice/":           "alice",
		"https://other.example/users/bob":           "bob", // path-shaped, host is not checked here
		"https://gw.example/@alice":                 "",
		"":                                          "",
	}
	for in, want := range cases {
		if got := userFromActorURL(in); got != want {
			t.Errorf("userFromActorURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRandomToken(t *testing.T) {
	a, b := randomToken(), randomToken()
	if len(a) != 16 {
		t.Fatalf("token = %q, want 16 hex chars", a)
	}
	if a == b {
		t.Fatal("tokens must not repeat; activity ids are derived from them")
	}
}

func TestIsSelfHostAndURL(t *testing.T) {
	g := testGateway(t) // host gw.example
	if !g.isSelfHost("GW.EXAMPLE") {
		t.Fatal("host matching must be case-insensitive")
	}
	if g.isSelfHost("other.example") {
		t.Fatal("a foreign host must not be self")
	}
	if !g.isSelfURL("https://gw.example/users/alice") {
		t.Fatal("our own actor url must be self")
	}
	if g.isSelfURL("https://other.example/users/alice") {
		t.Fatal("a remote url must not be self")
	}
	if g.isSelfURL("://nope") {
		t.Fatal("an unparsable url must not read as self")
	}

	t.Run("an empty host never matches", func(t *testing.T) {
		empty := &gateway{}
		if empty.isSelfHost("") {
			t.Fatal("an unconfigured gateway must not claim every host")
		}
	})
}

func TestCheckRemoteURLAppliesTheSSRFGuardWhenNotInTestMode(t *testing.T) {
	g := testGateway(t)
	g.allowPrivateTargets = false

	if err := g.checkRemoteURL("http://example.com/x"); !errors.Is(err, errInsecureURL) {
		t.Fatalf("http: err = %v", err)
	}
	if err := g.checkRemoteURL("https://127.0.0.1/x"); !errors.Is(err, errBlockedHost) {
		t.Fatalf("loopback: err = %v", err)
	}
	if err := g.checkRemoteURL(g.baseURL() + "/users/alice"); !errors.Is(err, errSelfTarget) {
		t.Fatalf("self: err = %v", err)
	}
	if err := g.checkRemoteURL("https://mastodon.social/users/bob"); err != nil {
		t.Fatalf("a public https url must pass: %v", err)
	}
}

func TestFetchKey(t *testing.T) {
	g := testGateway(t)
	f := newFakeInstance(t).attach(g)
	actorURL := f.actor("bob", &g.key.PublicKey)

	t.Run("resolves the actor's signing key", func(t *testing.T) {
		got, err := g.fetchKey(context.Background(), actorURL+"#main-key")
		if err != nil {
			t.Fatalf("fetchKey: %v", err)
		}
		if !got.Equal(&g.key.PublicKey) {
			t.Fatal("wrong key")
		}
	})

	t.Run("tolerates publicKey as an array", func(t *testing.T) {
		pem, perr := publicKeyPEM(g.key)
		if perr != nil {
			t.Fatal(perr)
		}
		f.serveDoc("/users/arr", contentTypeAP, map[string]any{
			"id": f.url("/users/arr"),
			"publicKey": []any{map[string]any{
				"id": f.url("/users/arr") + "#main-key", "publicKeyPem": pem,
			}},
		})
		if _, err := g.fetchKey(context.Background(), f.url("/users/arr")+"#main-key"); err != nil {
			t.Fatalf("array form: %v", err)
		}
	})

	t.Run("an actor without a key is malformed", func(t *testing.T) {
		f.serveDoc("/users/nokey", contentTypeAP, map[string]any{"id": f.url("/users/nokey")})
		if _, err := g.fetchKey(context.Background(), f.url("/users/nokey")); !errors.Is(err, errActorMalformed) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("an empty publicKeyPem is malformed", func(t *testing.T) {
		f.serveDoc("/users/emptypem", contentTypeAP, map[string]any{
			"id": f.url("/users/emptypem"), "publicKey": map[string]any{"id": "k"},
		})
		if _, err := g.fetchKey(context.Background(), f.url("/users/emptypem")); !errors.Is(err, errActorMalformed) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("an empty publicKey array is malformed", func(t *testing.T) {
		f.serveDoc("/users/emptyarr", contentTypeAP, map[string]any{
			"id": f.url("/users/emptyarr"), "publicKey": []any{},
		})
		if _, err := g.fetchKey(context.Background(), f.url("/users/emptyarr")); !errors.Is(err, errActorMalformed) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("an unreachable actor fails", func(t *testing.T) {
		if _, err := g.fetchKey(context.Background(), f.url("/users/ghost")+"#main-key"); err == nil {
			t.Fatal("expected an error for a 404 actor")
		}
	})
}

func TestFetchActorErrors(t *testing.T) {
	g := testGateway(t)
	f := newFakeInstance(t).attach(g)
	f.on("/notjson", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerContentType, contentTypeAP)
		_, _ = w.Write([]byte("<html>"))
	})

	if _, err := g.fetchActor(context.Background(), f.url("/missing")); !errors.Is(err, errRemoteStatus) {
		t.Fatalf("404: err = %v", err)
	}
	if _, err := g.fetchActor(context.Background(), f.url("/notjson")); err == nil {
		t.Fatal("a non-JSON actor document must fail")
	}
}

func TestRemoteInbox(t *testing.T) {
	g := testGateway(t)
	f := newFakeInstance(t).attach(g)
	ctx := context.Background()

	t.Run("prefers the shared inbox", func(t *testing.T) {
		f.serveDoc("/users/shared", contentTypeAP, map[string]any{
			"id": f.url("/users/shared"), "inbox": f.url("/users/shared/inbox"),
			"endpoints": map[string]any{"sharedInbox": f.url("/inbox")},
		})
		got, err := g.remoteInbox(ctx, f.url("/users/shared"))
		if err != nil {
			t.Fatal(err)
		}
		if got != f.url("/inbox") {
			t.Fatalf("inbox = %q, want the shared one", got)
		}
	})

	t.Run("falls back to the personal inbox", func(t *testing.T) {
		actorURL := f.actor("solo", nil)
		got, err := g.remoteInbox(ctx, actorURL)
		if err != nil {
			t.Fatal(err)
		}
		if got != actorURL+pathInbox {
			t.Fatalf("inbox = %q", got)
		}
	})

	t.Run("an empty sharedInbox falls through", func(t *testing.T) {
		f.serveDoc("/users/emptyshared", contentTypeAP, map[string]any{
			"id": f.url("/users/emptyshared"), "inbox": f.url("/users/emptyshared/inbox"),
			"endpoints": map[string]any{"sharedInbox": ""},
		})
		got, err := g.remoteInbox(ctx, f.url("/users/emptyshared"))
		if err != nil {
			t.Fatal(err)
		}
		if got != f.url("/users/emptyshared/inbox") {
			t.Fatalf("inbox = %q", got)
		}
	})

	t.Run("an actor with no inbox is malformed", func(t *testing.T) {
		f.serveDoc("/users/noinbox", contentTypeAP, map[string]any{"id": f.url("/users/noinbox")})
		if _, err := g.remoteInbox(ctx, f.url("/users/noinbox")); !errors.Is(err, errActorMalformed) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("an unreachable actor fails", func(t *testing.T) {
		if _, err := g.remoteInbox(ctx, f.url("/users/ghost")); err == nil {
			t.Fatal("expected an error")
		}
	})
}

func TestAPGetJSONAndArray(t *testing.T) {
	g := testGateway(t)
	f := newFakeInstance(t).attach(g)
	ctx := context.Background()

	f.serveDoc("/obj", "application/json", map[string]any{"a": 1})
	f.serveDoc("/arr", "application/json", []any{map[string]any{"id": "1"}})
	f.on("/broken", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("{{{")) })

	if m, err := g.apGetJSON(ctx, f.url("/obj"), "application/json"); err != nil || m["a"] != float64(1) {
		t.Fatalf("obj = %v, %v", m, err)
	}
	if a, err := g.apGetArray(ctx, f.url("/arr"), "application/json"); err != nil || len(a) != 1 {
		t.Fatalf("arr = %v, %v", a, err)
	}

	if _, err := g.apGetJSON(ctx, f.url("/missing"), "application/json"); !errors.Is(err, errRemoteStatus) {
		t.Fatalf("json 404: err = %v", err)
	}
	if _, err := g.apGetArray(ctx, f.url("/missing"), "application/json"); !errors.Is(err, errRemoteStatus) {
		t.Fatalf("array 404: err = %v", err)
	}
	if _, err := g.apGetJSON(ctx, f.url("/broken"), "application/json"); err == nil {
		t.Fatal("malformed JSON must fail")
	}
	if _, err := g.apGetArray(ctx, f.url("/obj"), "application/json"); err == nil {
		t.Fatal("an object is not an array")
	}
	// A blocked URL must never reach the network.
	if _, err := g.apGetJSON(ctx, g.baseURL()+"/x", "application/json"); !errors.Is(err, errSelfTarget) {
		t.Fatalf("self: err = %v", err)
	}
	if _, err := g.apGetArray(ctx, g.baseURL()+"/x", "application/json"); !errors.Is(err, errSelfTarget) {
		t.Fatalf("self array: err = %v", err)
	}
}

func TestFetchMedia(t *testing.T) {
	g := testGateway(t)
	f := newFakeInstance(t).attach(g)
	ctx := context.Background()

	f.on("/img.png", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerContentType, "image/png")
		_, _ = w.Write([]byte{0x89, 'P', 'N', 'G'})
	})

	mime, data, err := g.fetchMedia(ctx, f.url("/img.png"))
	if err != nil {
		t.Fatalf("fetchMedia: %v", err)
	}
	if mime != "image/png" || len(data) != 4 {
		t.Fatalf("mime = %q, %d bytes", mime, len(data))
	}
	if _, _, err := g.fetchMedia(ctx, f.url("/missing.png")); !errors.Is(err, errRemoteStatus) {
		t.Fatalf("404: err = %v", err)
	}
}

func TestPostSignedSurfacesTheRemoteRejection(t *testing.T) {
	g := testGateway(t)
	f := newFakeInstance(t).attach(g)
	f.on("/reject", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "signature verification failed", http.StatusUnauthorized)
	})

	err := g.postSigned(context.Background(), "alice", f.url("/reject"), activity{Type: typeCreate})
	if err == nil {
		t.Fatal("expected an error")
	}
	// Mastodon explains inbox rejections in the body; without it a failed
	// delivery is undiagnosable.
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("err = %v, want the peer's explanation included", err)
	}
	if !errors.Is(err, errRemoteStatus) {
		t.Fatalf("err = %v, want errRemoteStatus", err)
	}
}

func TestPostSignedDeliversASignedActivity(t *testing.T) {
	g := testGateway(t)
	f := newFakeInstance(t).attach(g)
	f.inbox("/inbox")

	doc := activity{Context: asContext, ID: "x#1", Type: typeCreate, Actor: g.actorID("alice")}
	if err := g.postSigned(context.Background(), "alice", f.url("/inbox"), doc); err != nil {
		t.Fatalf("postSigned: %v", err)
	}
	got := f.delivered()
	if len(got) != 1 {
		t.Fatalf("deliveries = %d", len(got))
	}
	if got[0].doc["type"] != typeCreate {
		t.Fatalf("delivered = %+v", got[0].doc)
	}
	if !strings.Contains(got[0].sig, g.keyID("alice")) {
		t.Fatalf("signature = %q, want it keyed to the local user's actor", got[0].sig)
	}
}

func TestRetryableStatus(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, 500, 502, 503} {
		if !retryableStatus(code) {
			t.Errorf("%d should be retried", code)
		}
	}
	for _, code := range []int{200, 301, 400, 403, 404, 410, 422} {
		if retryableStatus(code) {
			t.Errorf("%d should not be retried", code)
		}
	}
}

func TestSignGetIsANoOpWithoutAKey(t *testing.T) {
	g := &gateway{host: "gw.example"}
	req, err := http.NewRequest(http.MethodGet, "https://m/users/bob", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := g.signGet(req); err != nil {
		t.Fatalf("signGet: %v", err)
	}
	if req.Header.Get("Signature") != "" {
		t.Fatal("a keyless gateway must not pretend to sign")
	}
}

// A long rejection body must be truncated, not dumped whole into the log line.
func TestPostSignedTruncatesTheRejectionSnippet(t *testing.T) {
	g := testGateway(t)
	f := newFakeInstance(t).attach(g)
	long := strings.Repeat("x", 1000)
	f.on("/verbose", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, long, http.StatusBadRequest)
	})

	err := g.postSigned(context.Background(), "alice", f.url("/verbose"), activity{Type: typeCreate})
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), long) {
		t.Fatal("the whole body was included; the snippet must be capped")
	}
	if !strings.Contains(err.Error(), strings.Repeat("x", 300)) {
		t.Fatalf("err = %v, want the first 300 bytes kept", err)
	}
}

// A doc that cannot be marshalled must fail before anything is sent.
func TestPostSignedRejectsAnUnmarshalableDocument(t *testing.T) {
	g := testGateway(t)
	f := newFakeInstance(t).attach(g)
	f.inbox("/inbox")
	if err := g.postSigned(context.Background(), "alice", f.url("/inbox"), make(chan int)); err == nil {
		t.Fatal("expected a marshal error")
	}
	if len(f.delivered()) != 0 {
		t.Fatal("nothing must reach the peer")
	}
}
