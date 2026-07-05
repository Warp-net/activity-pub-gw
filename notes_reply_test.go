// Copyright 2025 Vadim Filin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
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
