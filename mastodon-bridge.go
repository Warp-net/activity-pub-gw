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

// mastodonBridge converts between Warpnet and the Fediverse over ActivityPub:
// reads resolve a WebFinger handle to a remote actor and render it into Warpnet
// domain types; writes federate a Warpnet action (like, follow, reply, boost)
// as a signed activity delivered to the target author's inbox. It depends only
// on apTransport, so the conversion logic is isolated from the HTTP/libp2p
// machinery on the gateway.

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/Warp-net/warpnet/domain"
	"github.com/Warp-net/warpnet/event"
)

// apTransport is the ActivityPub HTTP surface the bridge needs; *gateway
// implements it (reusing its SSRF-hardened client and signing keys).
type apTransport interface {
	apGetJSON(ctx context.Context, rawURL, accept string) (map[string]any, error)
	fetchActor(ctx context.Context, actorURL string) (map[string]any, error)
	remoteInbox(ctx context.Context, actorURL string) (string, error)
	actorID(user string) string
	postSigned(ctx context.Context, localUser, target string, doc any) error
	deliverFollow(localUser, remoteActorURL string, undo bool)
	fetchMedia(ctx context.Context, rawURL string) (mimeType string, data []byte, err error)
}

type mastodonBridge struct {
	ap     apTransport
	nodeID string // gateway peer id stamped onto bridged users
}

func newMastodonBridge(ap apTransport, nodeID string) *mastodonBridge {
	return &mastodonBridge{ap: ap, nodeID: nodeID}
}

// resolveHandle resolves "name@instance" to its actor URL via WebFinger.
func (b *mastodonBridge) resolveHandle(ctx context.Context, handle string) (string, error) {
	name, instance, ok := strings.Cut(strings.TrimPrefix(handle, "@"), "@")
	if !ok || name == "" || instance == "" {
		return "", fmt.Errorf("mastodon: %q is not a name@instance handle", handle)
	}
	wf := "https://" + instance + "/.well-known/webfinger?resource=acct:" + name + "@" + instance
	doc, err := b.ap.apGetJSON(ctx, wf, contentTypeJRD)
	if err != nil {
		return "", fmt.Errorf("mastodon: webfinger %s: %w", handle, err)
	}
	for _, l := range asSlice(doc["links"]) {
		link := asMap(l)
		if link == nil || asString(link["rel"]) != "self" {
			continue
		}
		if href, _ := link["href"].(string); href != "" {
			return href, nil
		}
	}
	return "", fmt.Errorf("mastodon: webfinger %s: no self link", handle)
}

// --- reads (Mastodon -> Warpnet) ---

func (b *mastodonBridge) GetUser(ctx context.Context, handle string) (user, error) {
	actorURL, err := b.resolveHandle(ctx, handle)
	if err != nil {
		return user{}, err
	}
	m, err := b.ap.fetchActor(ctx, actorURL)
	if err != nil {
		return user{}, err
	}
	return actorToUser(handle, actorURL, m, b.nodeID), nil
}

// GetTweets renders a remote actor's outbox as Warpnet tweets. cursor, when set,
// is the next OrderedCollectionPage URL.
func (b *mastodonBridge) GetTweets(ctx context.Context, handle string, cursor *string) (tweetsResponse, error) {
	pageURL := ""
	if cursor != nil {
		pageURL = *cursor
	}
	if pageURL == "" {
		actorURL, err := b.resolveHandle(ctx, handle)
		if err != nil {
			return tweetsResponse{}, err
		}
		actor, err := b.ap.fetchActor(ctx, actorURL)
		if err != nil {
			return tweetsResponse{}, err
		}
		outbox := asString(actor["outbox"])
		if outbox == "" {
			return tweetsResponse{UserId: handle}, nil
		}
		ob, err := b.ap.apGetJSON(ctx, outbox, contentTypeAP)
		if err != nil {
			return tweetsResponse{}, err
		}
		if pageURL = asString(ob["first"]); pageURL == "" {
			return tweetsResponse{UserId: handle}, nil
		}
	}

	page, err := b.ap.apGetJSON(ctx, pageURL, contentTypeAP)
	if err != nil {
		return tweetsResponse{}, err
	}
	resp := tweetsResponse{UserId: handle, Cursor: asString(page["next"])}
	for _, it := range asSlice(page["orderedItems"]) {
		obj := asMap(it)
		if obj == nil {
			continue
		}
		if t, ok := b.activityToTweet(ctx, handle, obj); ok {
			resp.Tweets = append(resp.Tweets, t)
		}
	}
	return resp, nil
}

// activityToTweet turns one outbox item (Create wrapping a Note, a bare Note, or
// an Announce boost) into a tweet.
func (b *mastodonBridge) activityToTweet(ctx context.Context, handle string, obj map[string]any) (tweet, bool) {
	if asString(obj["type"]) == typeAnnounce {
		boosted := asString(obj["object"])
		if boosted == "" {
			return tweet{}, false
		}
		bm, err := b.ap.apGetJSON(ctx, boosted, contentTypeAP)
		if err != nil {
			return tweet{}, false
		}
		t, ok := noteToTweet(handleFromActorURL(asString(bm["attributedTo"])), bm)
		if ok {
			by := handle
			t.RetweetedBy = &by
		}
		return t, ok
	}
	note := obj
	if inner := asMap(obj["object"]); inner != nil {
		note = inner
	}
	return noteToTweet(handle, note)
}

// GetTweet fetches a single Note by its id (the AP object URL stored as tweet id).
func (b *mastodonBridge) GetTweet(ctx context.Context, noteURL string) (tweet, error) {
	m, err := b.ap.apGetJSON(ctx, strings.TrimPrefix(noteURL, domain.RetweetPrefix), contentTypeAP)
	if err != nil {
		return tweet{}, err
	}
	if inner := asMap(m["object"]); inner != nil {
		m = inner
	}
	t, _ := noteToTweet(handleFromActorURL(asString(m["attributedTo"])), m)
	return t, nil
}

// GetReplies fetches the first page of a Note's replies collection.
func (b *mastodonBridge) GetReplies(ctx context.Context, noteURL string) (repliesResponse, error) {
	m, err := b.ap.apGetJSON(ctx, strings.TrimPrefix(noteURL, domain.RetweetPrefix), contentTypeAP)
	if err != nil {
		return repliesResponse{}, err
	}
	resp := repliesResponse{Replies: []domain.ReplyNode{}}
	repliesURL := asString(m["replies"])
	if repliesURL == "" {
		return resp, nil
	}
	coll, err := b.ap.apGetJSON(ctx, repliesURL, contentTypeAP)
	if err != nil {
		return resp, nil //nolint:nilerr // hidden/absent replies -> empty, not an error
	}
	page := asMap(coll["first"])
	if page == nil {
		if u := asString(coll["first"]); u != "" {
			page, _ = b.ap.apGetJSON(ctx, u, contentTypeAP)
		}
	}
	if page == nil {
		return resp, nil
	}
	for _, it := range asSlice(page["items"]) {
		note := asMap(it)
		if note == nil {
			continue
		}
		if t, ok := noteToTweet(handleFromActorURL(asString(note["attributedTo"])), note); ok {
			resp.Replies = append(resp.Replies, domain.ReplyNode{Reply: t})
		}
	}
	return resp, nil
}

// GetTweetStats reads the like/boost/reply counts off the Note.
func (b *mastodonBridge) GetTweetStats(ctx context.Context, noteURL string) (event.TweetStatsResponse, error) {
	noteURL = strings.TrimPrefix(noteURL, domain.RetweetPrefix)
	m, err := b.ap.apGetJSON(ctx, noteURL, contentTypeAP)
	if err != nil {
		return event.TweetStatsResponse{}, err
	}
	if inner := asMap(m["object"]); inner != nil {
		m = inner
	}
	return event.TweetStatsResponse{
		TweetId:       domain.ID(noteURL),
		LikeCount:     apCollectionCount(m["likes"]),
		RetweetsCount: apCollectionCount(m["shares"]),
		RepliesCount:  apCollectionCount(m["replies"]),
	}, nil
}

func (b *mastodonBridge) GetFollowers(ctx context.Context, handle string, cursor *string) (followersResponse, error) {
	ids, next, err := b.followList(ctx, handle, cursor, "followers")
	if err != nil {
		return followersResponse{}, err
	}
	return followersResponse{FollowingId: handle, Followers: ids, Cursor: next}, nil
}

func (b *mastodonBridge) GetFollowings(ctx context.Context, handle string, cursor *string) (followingsResponse, error) {
	ids, next, err := b.followList(ctx, handle, cursor, "following")
	if err != nil {
		return followingsResponse{}, err
	}
	return followingsResponse{FollowerId: handle, Followings: ids, Cursor: next}, nil
}

// followList resolves the actor's follower/following collection to handles.
// Instances that hide the member list yield an empty result.
func (b *mastodonBridge) followList(ctx context.Context, handle string, cursor *string, field string) ([]string, string, error) {
	pageURL := ""
	if cursor != nil {
		pageURL = *cursor
	}
	if pageURL == "" {
		actorURL, err := b.resolveHandle(ctx, handle)
		if err != nil {
			return nil, "", err
		}
		actor, err := b.ap.fetchActor(ctx, actorURL)
		if err != nil {
			return nil, "", err
		}
		coll := asString(actor[field])
		if coll == "" {
			return []string{}, "", nil
		}
		page, perr := b.ap.apGetJSON(ctx, coll, contentTypeAP)
		if perr != nil {
			return []string{}, "", nil //nolint:nilerr // hidden collection -> empty, not an error
		}
		hasItems := len(asSlice(page["orderedItems"])) > 0 || len(asSlice(page["items"])) > 0
		if first := asString(page["first"]); first != "" && !hasItems {
			pageURL = first
		} else {
			return collectHandles(page), asString(page["next"]), nil
		}
	}
	page, err := b.ap.apGetJSON(ctx, pageURL, contentTypeAP)
	if err != nil {
		return []string{}, "", nil //nolint:nilerr // hidden collection -> empty, not an error
	}
	return collectHandles(page), asString(page["next"]), nil
}

func (b *mastodonBridge) GetImage(ctx context.Context, rawURL string) (getImageResponse, error) {
	mime, data, err := b.ap.fetchMedia(ctx, rawURL)
	if err != nil {
		return getImageResponse{}, err
	}
	if mime == "" {
		mime = "image/jpeg"
	}
	return getImageResponse{File: mime + "," + base64.StdEncoding.EncodeToString(data)}, nil
}

// --- writes (Warpnet -> Mastodon) ---

// Like federates a like (or its undo) and returns the status's like count.
func (b *mastodonBridge) Like(ctx context.Context, localUser, objectURL string, undo bool) (uint64, error) {
	note, inbox, err := b.authorInbox(ctx, objectURL)
	if err != nil {
		return 0, err
	}
	actorID := b.ap.actorID(localUser)
	like := activity{Context: asContext, ID: actorID + "#like-" + randomToken(), Type: typeLike, Actor: actorID, Object: asString(note["id"])}
	if derr := b.ap.postSigned(ctx, localUser, inbox, undoIf(actorID, like, undo)); derr != nil {
		return 0, derr
	}
	return apCollectionCount(note["likes"]), nil
}

// Announce federates a boost (or its undo) of objectURL.
func (b *mastodonBridge) Announce(ctx context.Context, localUser, objectURL string, undo bool) error {
	note, inbox, err := b.authorInbox(ctx, objectURL)
	if err != nil {
		return err
	}
	actorID := b.ap.actorID(localUser)
	announce := activity{Context: asContext, ID: actorID + "#announce-" + randomToken(), Type: typeAnnounce, Actor: actorID, Object: asString(note["id"]), To: []string{asPublic}}
	return b.ap.postSigned(ctx, localUser, inbox, undoIf(actorID, announce, undo))
}

// Follow federates a follow (or its undo) of a Mastodon handle.
func (b *mastodonBridge) Follow(ctx context.Context, localUser, followingHandle string, undo bool) error {
	actorURL, err := b.resolveHandle(ctx, followingHandle)
	if err != nil {
		return err
	}
	b.ap.deliverFollow(localUser, actorURL, undo)
	return nil
}

// Reply federates a Warpnet reply as a Create(Note) inReplyTo the parent.
func (b *mastodonBridge) Reply(ctx context.Context, ev newReplyEvent) error {
	parentURL := string(ev.RootId)
	if ev.ParentId != nil && *ev.ParentId != "" {
		parentURL = string(*ev.ParentId)
	}
	obj, inbox, err := b.authorInbox(ctx, parentURL)
	if err != nil {
		return err
	}
	// Address the parent author (To) with the public collection in Cc, so the
	// reply is delivered/notified to them and shown publicly, not just threaded.
	author := asString(obj["attributedTo"])
	localUser := string(ev.UserId)
	actorID := b.ap.actorID(localUser)
	n := note{
		Context:      asContext,
		ID:           actorID + "/statuses/" + randomToken(),
		Type:         typeNote,
		AttributedTo: actorID,
		Content:      ev.Text,
		Published:    time.Now().UTC().Format(time.RFC3339),
		InReplyTo:    parentURL,
		To:           []string{author},
		Cc:           []string{asPublic},
	}
	create := activity{Context: asContext, ID: n.ID + "#create", Type: typeCreate, Actor: actorID, Object: n, To: []string{author}, Cc: []string{asPublic}}
	return b.ap.postSigned(ctx, localUser, inbox, create)
}

// authorInbox fetches an object (Note) once and resolves its author's inbox,
// returning the fetched note so callers can also read its counts.
func (b *mastodonBridge) authorInbox(ctx context.Context, objectURL string) (map[string]any, string, error) {
	m, err := b.ap.apGetJSON(ctx, strings.TrimPrefix(objectURL, domain.RetweetPrefix), contentTypeAP)
	if err != nil {
		return nil, "", err
	}
	if inner := asMap(m["object"]); inner != nil {
		m = inner
	}
	author := asString(m["attributedTo"])
	if author == "" {
		return nil, "", fmt.Errorf("mastodon: object %s has no attributedTo", objectURL)
	}
	inbox, err := b.ap.remoteInbox(ctx, author)
	return m, inbox, err
}

// undoIf wraps an activity in an Undo when undo is set.
func undoIf(actorID string, inner activity, undo bool) any {
	if !undo {
		return inner
	}
	return activity{Context: asContext, ID: actorID + "#undo-" + randomToken(), Type: typeUndo, Actor: actorID, Object: inner}
}
