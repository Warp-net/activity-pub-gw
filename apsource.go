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

// apsource maps Mastodon/Fediverse accounts and posts into Warpnet's own
// domain types so they can be served over libp2p to Warpnet nodes (the
// Mastodon -> Warpnet direction). It is read-only and reuses the gateway's
// SSRF-hardened fetchActor; users are addressed by their WebFinger handle
// (name@instance), which is also the Warpnet user id, so any node request
// round-trips back to the same account.

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/Warp-net/warpnet/domain"
	"github.com/Warp-net/warpnet/event"
	stripper "github.com/grokify/html-strip-tags-go"
	log "github.com/sirupsen/logrus"
)

// mastodonNetwork tags bridged users/tweets so Warpnet treats them as a foreign
// network. It mirrors warpnet's own "mastodon" User.Network value on the wire
// (kept local so the gateway needn't pin a warpnet version that exports it).
const mastodonNetwork = "mastodon"

// apGetJSON fetches and decodes an arbitrary JSON document (WebFinger / AP
// collection), reusing the gateway's SSRF guard. Actor documents go through
// fetchActor instead (it signs for authorized-fetch instances).
func (g *gateway) apGetJSON(ctx context.Context, rawURL, accept string) (map[string]any, error) {
	if !g.allowPrivateTargets {
		if err := validateRemoteURL(rawURL); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil) //nolint:gosec // SSRF-guarded above + safe client
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	resp, err := g.client.Do(req) //nolint:gosec // see note above
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: status %d: %w", rawURL, resp.StatusCode, errRemoteStatus)
	}
	bt, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, err
	}
	return decodeJSONObject(bt)
}

// apResolveHandle resolves a "name@instance" handle to its actor URL via
// WebFinger.
func (g *gateway) apResolveHandle(ctx context.Context, handle string) (string, error) {
	name, instance, ok := strings.Cut(strings.TrimPrefix(handle, "@"), "@")
	if !ok || name == "" || instance == "" {
		return "", fmt.Errorf("apsource: %q is not a name@instance handle", handle)
	}
	wf := "https://" + instance + "/.well-known/webfinger?resource=acct:" + name + "@" + instance
	doc, err := g.apGetJSON(ctx, wf, contentTypeJRD)
	if err != nil {
		return "", fmt.Errorf("apsource: webfinger %s: %w", handle, err)
	}
	for _, l := range asSlice(doc["links"]) {
		link, _ := l.(map[string]any)
		if link == nil {
			continue
		}
		if s, _ := link["rel"].(string); s != "self" {
			continue
		}
		if href, _ := link["href"].(string); href != "" {
			return href, nil
		}
	}
	return "", fmt.Errorf("apsource: webfinger %s: no self link", handle)
}

// apGetUser resolves a handle and renders the remote actor as a Warpnet user.
func (g *gateway) apGetUser(ctx context.Context, handle string) (domain.User, error) {
	actorURL, err := g.apResolveHandle(ctx, handle)
	if err != nil {
		return domain.User{}, err
	}
	m, err := g.fetchActor(ctx, actorURL)
	if err != nil {
		return domain.User{}, err
	}
	return g.apActorToUser(handle, actorURL, m), nil
}

func (g *gateway) apActorToUser(handle, actorURL string, m map[string]any) domain.User {
	name, _ := m["name"].(string)
	if name == "" {
		name, _ = m["preferredUsername"].(string)
	}
	u := domain.User{
		Id:        handle,
		Username:  name,
		Bio:       stripper.StripTags(asString(m["summary"])),
		NodeId:    g.nodeID,
		Network:   mastodonNetwork,
		AvatarKey: asImageURL(m["icon"]),
		CreatedAt: parseAPTime(asString(m["published"])),
	}
	u.BackgroundImageKey = asImageURL(m["image"])
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}
	if site := actorURL; site != "" {
		u.Website = &site
	}
	return u
}

// apGetTweets renders a remote actor's outbox as Warpnet tweets. cursor, when
// set, is the next OrderedCollectionPage URL.
func (g *gateway) apGetTweets(ctx context.Context, handle string, cursor *string) (event.TweetsResponse, error) {
	pageURL := ""
	if cursor != nil {
		pageURL = *cursor
	}
	if pageURL == "" {
		actorURL, err := g.apResolveHandle(ctx, handle)
		if err != nil {
			return event.TweetsResponse{}, err
		}
		actor, err := g.fetchActor(ctx, actorURL)
		if err != nil {
			return event.TweetsResponse{}, err
		}
		outbox := asString(actor["outbox"])
		if outbox == "" {
			return event.TweetsResponse{}, nil
		}
		ob, err := g.apGetJSON(ctx, outbox, contentTypeAP)
		if err != nil {
			return event.TweetsResponse{}, err
		}
		pageURL = asString(ob["first"])
		if pageURL == "" {
			return event.TweetsResponse{UserId: handle}, nil
		}
	}

	page, err := g.apGetJSON(ctx, pageURL, contentTypeAP)
	if err != nil {
		return event.TweetsResponse{}, err
	}
	resp := event.TweetsResponse{UserId: handle, Cursor: asString(page["next"])}
	for _, it := range asSlice(page["orderedItems"]) {
		obj, _ := it.(map[string]any)
		if obj == nil {
			continue
		}
		// orderedItems are activities (Create) wrapping the Note, or bare Notes.
		note := obj
		if inner := asMap(obj["object"]); inner != nil {
			note = inner
		}
		if t, ok := g.apNoteToTweet(handle, note); ok {
			resp.Tweets = append(resp.Tweets, t)
		}
	}
	return resp, nil
}

// apGetTweet fetches a single Note by its id (the AP object URL stored as the
// tweet id).
func (g *gateway) apGetTweet(ctx context.Context, noteURL string) (domain.Tweet, error) {
	noteURL = strings.TrimPrefix(noteURL, domain.RetweetPrefix)
	m, err := g.apGetJSON(ctx, noteURL, contentTypeAP)
	if err != nil {
		return domain.Tweet{}, err
	}
	if inner := asMap(m["object"]); inner != nil { // a Create activity URL
		m = inner
	}
	t, _ := g.apNoteToTweet(handleFromActorURL(asString(m["attributedTo"])), m)
	return t, nil
}

// apGetReplies fetches the replies collection of a Note.
func (g *gateway) apGetReplies(ctx context.Context, noteURL string) (event.RepliesResponse, error) {
	noteURL = strings.TrimPrefix(noteURL, domain.RetweetPrefix)
	m, err := g.apGetJSON(ctx, noteURL, contentTypeAP)
	if err != nil {
		return event.RepliesResponse{}, err
	}
	resp := event.RepliesResponse{Replies: []domain.ReplyNode{}}
	repliesURL := asString(m["replies"])
	if repliesURL == "" {
		return resp, nil
	}
	coll, err := g.apGetJSON(ctx, repliesURL, contentTypeAP)
	if err != nil {
		return resp, nil //nolint:nilerr // missing/forbidden replies collection -> empty, not an error
	}
	first := coll["first"]
	page := asMap(first)
	if page == nil {
		if u := asString(first); u != "" {
			page, _ = g.apGetJSON(ctx, u, contentTypeAP)
		}
	}
	if page == nil {
		return resp, nil
	}
	for _, it := range asSlice(page["items"]) {
		note := asMap(it)
		if note == nil {
			continue // bare id strings: the referenced note must be fetched separately
		}
		if t, ok := g.apNoteToTweet(handleFromActorURL(asString(note["attributedTo"])), note); ok {
			resp.Replies = append(resp.Replies, domain.ReplyNode{Reply: t})
		}
	}
	return resp, nil
}

// apGetImage fetches a remote media URL and returns it as Warpnet's
// "<mime>,<base64>" image payload.
func (g *gateway) apGetImage(ctx context.Context, rawURL string) (event.GetImageResponse, error) {
	if !g.allowPrivateTargets {
		if err := validateRemoteURL(rawURL); err != nil {
			return event.GetImageResponse{}, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil) //nolint:gosec // SSRF-guarded + safe client
	if err != nil {
		return event.GetImageResponse{}, err
	}
	resp, err := g.client.Do(req) //nolint:gosec // see note above
	if err != nil {
		return event.GetImageResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return event.GetImageResponse{}, fmt.Errorf("image %s: status %d: %w", rawURL, resp.StatusCode, errRemoteStatus)
	}
	bt, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return event.GetImageResponse{}, err
	}
	mime := resp.Header.Get(headerContentType)
	if mime == "" {
		mime = "image/jpeg"
	}
	return event.GetImageResponse{File: mime + "," + base64.StdEncoding.EncodeToString(bt)}, nil
}

// apNoteToTweet maps an ActivityPub Note object to a Warpnet tweet. Non-Note
// objects (and empties) are skipped.
func (g *gateway) apNoteToTweet(authorHandle string, note map[string]any) (domain.Tweet, bool) {
	if t, _ := note["type"].(string); t != typeNote {
		return domain.Tweet{}, false
	}
	id := asString(note["id"])
	if id == "" {
		return domain.Tweet{}, false
	}
	parent := asString(note["inReplyTo"])
	author := asString(note["attributedTo"])
	username := authorHandle
	if username == "" {
		username = handleFromActorURL(author)
	}
	t := domain.Tweet{
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

// asImageURL extracts the url of an AP image object (icon/image), tolerating the
// bare-string and array forms.
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
		log.Debugf("apsource: bad published time %q: %v", s, err)
		return time.Time{}
	}
	return t
}
