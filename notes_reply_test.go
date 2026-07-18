// Copyright 2025 Vadim Filin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// TestBuildNoteThreadsReplies verifies a reply carries inReplyTo so Mastodon can
// thread it, while an original post does not.
func TestBuildNoteThreadsReplies(t *testing.T) {
	g := testGateway(t)
	actor := g.actorID("alice")
	parent := "01PARENT0000000000000000000"
	root := "01ROOT000000000000000000000"

	parentID := parent
	cases := []struct {
		name string
		in   tweet
		want string
	}{
		{
			name: "top-level post has no inReplyTo",
			in:   tweet{Id: "01SELF000000000000000000000", UserId: "alice", CreatedAt: time.Unix(0, 0)},
			want: "",
		},
		{
			name: "top-level post whose RootId is itself has no inReplyTo",
			in:   tweet{Id: root, RootId: root, UserId: "alice", CreatedAt: time.Unix(0, 0)},
			want: "",
		},
		{
			name: "reply with ParentId links to the parent",
			in:   tweet{Id: "01REPLY00000000000000000000", ParentId: &parentID, RootId: root, UserId: "alice", CreatedAt: time.Unix(0, 0)},
			want: actor + pathStatuses + parent,
		},
		{
			name: "reply off the root (no ParentId) links to the root",
			in:   tweet{Id: "01REPLY20000000000000000000", RootId: root, UserId: "alice", CreatedAt: time.Unix(0, 0)},
			want: actor + pathStatuses + root,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := g.buildNote("alice", tc.in).InReplyTo; got != tc.want {
				t.Fatalf("InReplyTo = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestReplyEventFromTweet verifies a reply forwarded over the private tweet
// route (a tweet with a parent) is adapted into the reply event the bridge
// federates, carrying the thread ids, author and text.
func TestReplyEventFromTweet(t *testing.T) {
	parent := "https://m/users/bob/statuses/9"
	pid := parent
	in := tweet{
		Id:        "01REPLY00000000000000000000",
		ParentId:  &pid,
		RootId:    "https://m/users/bob/statuses/1",
		Text:      "Cool!",
		UserId:    "01USER0000000000000000000",
		Username:  "Vadim",
		CreatedAt: time.Unix(0, 0),
	}
	re := replyEventFromTweet(in)
	if re.ParentId == nil || *re.ParentId != parent {
		t.Fatalf("ParentId = %v, want %q", re.ParentId, parent)
	}
	if re.Id != "01REPLY00000000000000000000" || re.RootId != "https://m/users/bob/statuses/1" {
		t.Fatalf("ids: %+v", re)
	}
	if re.Text != "Cool!" || re.UserId != "01USER0000000000000000000" || re.Username != "Vadim" {
		t.Fatalf("fields: %+v", re)
	}
}

// TestServeRepliesUsesTweetsAPI verifies the replies collection is sourced from
// PUBLIC_GET_TWEETS with the note as parent_id (warpnet retired the standalone
// PUBLIC_GET_REPLIES route), and that fediverse-authored replies are skipped.
func TestServeRepliesUsesTweetsAPI(t *testing.T) {
	g := testGateway(t)
	parent := "01PARENT0000000000000000000"
	native := tweet{
		Id: "01REPLY00000000000000000000", ParentId: &parent, RootId: parent,
		UserId: "alice", Username: "alice", Text: "native reply", CreatedAt: time.Unix(0, 0),
	}
	foreign := tweet{
		Id: "01REPLY20000000000000000000", ParentId: &parent, RootId: parent,
		UserId: apFollowerPrefix + "xxx", Username: "bob@m", Text: "foreign reply", CreatedAt: time.Unix(0, 0),
	}
	bt, _ := json.Marshal(tweetsResponse{Tweets: []tweet{native, foreign}})
	fr := &fakeRequester{tweetsJSON: bt}
	g.req = fr

	w := httptest.NewRecorder()
	g.serveReplies(w, "alice", parent)

	if fr.lastRoute != routeGetTweets {
		t.Fatalf("route = %q, want %q", fr.lastRoute, routeGetTweets)
	}
	req, ok := fr.lastPayload.(getTweetsRequest)
	if !ok || req.ParentId != parent || req.UserId != "alice" {
		t.Fatalf("payload = %+v", fr.lastPayload)
	}

	var col orderedCollection
	if err := json.Unmarshal(w.Body.Bytes(), &col); err != nil {
		t.Fatalf("decode collection: %v", err)
	}
	if col.TotalItems != 1 || len(col.OrderedItems) != 1 {
		t.Fatalf("items = %d, want 1 (fediverse reply must be skipped)", col.TotalItems)
	}
}
