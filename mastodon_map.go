/*

 Warpnet - Decentralized Social Network
 Copyright (C) 2025 Vadim Filin, https://github.com/Warp-net,
 <github.com.mecdy@passmail.net>

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <https://www.gnu.org/licenses/>.

WarpNet is provided “as is” without warranty of any kind, either expressed or implied.
Use at your own risk. The maintainers shall not be liable for any damages or data loss
resulting from the use or misuse of this software.
*/

// Copyright 2025 Vadim Filin
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// mastodon_map holds the pure conversion from loosely-typed ActivityPub
// documents to Warpnet's domain types. These functions have no I/O and no
// dependency on the gateway, so they are trivially unit-testable.

import (
	"strings"
	"time"

	stripper "github.com/grokify/html-strip-tags-go"
	log "github.com/sirupsen/logrus"
)

// mastodonNetwork tags bridged users/tweets so Warpnet treats them as a foreign
// network; mirrors warpnet's own "mastodon" User.Network value on the wire.
const mastodonNetwork = "mastodon"

// actorToUser renders an ActivityPub actor document as a Warpnet user. handle is
// the WebFinger id (and the Warpnet user id); nodeID is the gateway peer that
// serves it.
func actorToUser(handle, actorURL string, m map[string]any, nodeID string) user {
	name, _ := m["name"].(string)
	if name == "" {
		name, _ = m["preferredUsername"].(string)
	}
	u := user{
		Id:                 handle,
		Username:           name,
		Bio:                stripper.StripTags(asString(m["summary"])),
		NodeId:             nodeID,
		Network:            mastodonNetwork,
		AvatarKey:          asImageURL(m["icon"]),
		BackgroundImageKey: asImageURL(m["image"]),
		CreatedAt:          parseAPTime(asString(m["published"])),
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}
	if actorURL != "" {
		site := actorURL
		u.Website = &site
	}
	return u
}

// noteToTweet maps an ActivityPub Note to a Warpnet tweet. Non-Note objects are
// skipped (ok=false).
func noteToTweet(authorHandle string, note map[string]any) (tweet, bool) {
	if t, _ := note["type"].(string); t != typeNote {
		return tweet{}, false
	}
	id := asString(note["id"])
	if id == "" {
		return tweet{}, false
	}
	parent := asString(note["inReplyTo"])
	username := authorHandle
	if username == "" {
		username = handleFromActorURL(asString(note["attributedTo"]))
	}
	t := tweet{
		Id:        id,
		RootId:    parent,
		ParentId:  &parent,
		Text:      stripper.StripTags(asString(note["content"])),
		UserId:    username,
		Username:  username,
		CreatedAt: parseAPTime(asString(note["published"])),
		Network:   mastodonNetwork,
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	for _, a := range asSlice(note["attachment"]) {
		att := asMap(a)
		if att == nil {
			continue
		}
		if mt, _ := att["mediaType"].(string); !strings.HasPrefix(mt, "image/") {
			continue
		}
		if u := asString(att["url"]); u != "" {
			t.ImageKeys = append(t.ImageKeys, u)
		}
	}
	return t, true
}

// collectHandles maps a collection page's actor-URL items to Fediverse handles.
func collectHandles(page map[string]any) []string {
	items := asSlice(page["orderedItems"])
	if len(items) == 0 {
		items = asSlice(page["items"])
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		if u := asString(it); u != "" {
			out = append(out, handleFromActorURL(u))
		}
	}
	return out
}

// apCollectionCount reads totalItems off an AP Collection value.
func apCollectionCount(v any) uint64 {
	m := asMap(v)
	if m == nil {
		return 0
	}
	if n, ok := m["totalItems"].(float64); ok && n > 0 {
		return uint64(n)
	}
	return 0
}

// asImageURL extracts the url of an AP image (icon/image), tolerating the bare
// string, object, and array forms.
func asImageURL(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case map[string]any:
		return asString(x["url"])
	case []any:
		if len(x) > 0 {
			return asImageURL(x[0])
		}
	}
	return ""
}

func parseAPTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		log.Debugf("mastodon: bad published time %q: %v", s, err)
		return time.Time{}
	}
	return t
}

// asString reads a string from a loosely-typed AP value, tolerating the
// {"id": "..."} object form.
func asString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case map[string]any:
		id, _ := x["id"].(string)
		return id
	}
	return ""
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}
