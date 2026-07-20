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

// nodeserver is the libp2p transport for the Mastodon -> Warpnet direction: it
// answers Warpnet's public /public routes. To a Warpnet node the gateway is an
// ordinary member peer — it reports node info with a hardcoded Mastodon owner
// and resolves every request through the mastodonBridge. It verifies the
// caller's signature (like the node's auth middleware) but holds no domain
// logic itself, and does NOT register the spoof-challenge route (it is not a
// Warpnet-codebase node; discovery tolerates that).

import (
	"context"
	"io"
	"time"

	"github.com/Masterminds/semver/v3"
	"github.com/Warp-net/warpnet/core/warpnet"
	"github.com/Warp-net/warpnet/event"
	wjson "github.com/Warp-net/warpnet/json"
	"github.com/Warp-net/warpnet/security"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/protocol"
	log "github.com/sirupsen/logrus"
)

const (
	// maxRequestBytes bounds an inbound request envelope (the written response,
	// e.g. an image, is not capped here).
	maxRequestBytes = 1 << 20
	// apRequestTimeout bounds the ActivityPub work to answer one node request.
	apRequestTimeout = 30 * time.Second
)

// routeHandler answers one public route from the signed request body.
type routeHandler func(ctx context.Context, body []byte) (any, error)

// serveRoutes registers the gateway as a libp2p server for Warpnet's public
// routes, delegating all domain work to the bridge. ownerHandle is the Mastodon
// account advertised as the node owner.
func (c *nodeClient) serveRoutes(g *gateway, ownerHandle string) {
	b := newMastodonBridge(g, c.h.ID().String())

	handlers := map[string]routeHandler{
		event.PUBLIC_GET_INFO: c.infoHandler(ownerHandle),

		routeGetUser: wrapJSON(func(ctx context.Context, ev getUserEvent) (any, error) {
			return b.GetUser(ctx, string(ev.UserId))
		}),
		routeGetUsers: wrapJSON(func(ctx context.Context, ev getAllUsersEvent) (any, error) {
			u, err := b.GetUserBrief(ctx, string(ev.UserId)) // list context: skip count fetches
			if err != nil {
				return event.UsersResponse{}, nil //nolint:nilerr // unknown handle -> empty
			}
			return event.UsersResponse{Users: []user{u}}, nil
		}),
		routeGetTweets: wrapJSON(func(ctx context.Context, ev getTweetsRequest) (any, error) {
			return b.GetTweetsOrReplies(ctx, ev)
		}),
		routeGetTweet: wrapJSON(func(ctx context.Context, ev getTweetEvent) (any, error) {
			return b.GetTweet(ctx, string(ev.TweetId))
		}),
		routeGetReplies: wrapJSON(func(ctx context.Context, ev getRepliesEvent) (any, error) {
			// The note whose replies are wanted is the parent (a specific reply)
			// or the thread root for top-level replies; both are AP note URLs.
			id := string(ev.ParentId)
			if id == "" {
				id = string(ev.RootId)
			}
			return b.GetReplies(ctx, id)
		}),
		event.PUBLIC_GET_TWEET_STATS: wrapJSON(func(ctx context.Context, ev getTweetEvent) (any, error) {
			return b.GetTweetStats(ctx, string(ev.TweetId))
		}),
		routeGetFollowers: wrapJSON(func(ctx context.Context, ev getFollowersEvent) (any, error) {
			return b.GetFollowers(ctx, string(ev.UserId), ev.Cursor)
		}),
		routeGetFollowings: wrapJSON(func(ctx context.Context, ev getFollowersEvent) (any, error) {
			return b.GetFollowings(ctx, string(ev.UserId), ev.Cursor)
		}),
		routeGetImage: wrapJSON(func(ctx context.Context, ev getImageEvent) (any, error) {
			return b.GetImage(ctx, ev.Key)
		}),
		event.PUBLIC_POST_VIEW: func(context.Context, []byte) (any, error) {
			return event.ViewsCountResponse{Count: 1}, nil
		},

		routePostLike: wrapJSON(func(ctx context.Context, ev likeEvent) (any, error) {
			count, err := b.Like(ctx, string(ev.OwnerId), string(ev.TweetId), false)
			return event.LikesCountResponse{Count: count}, err
		}),
		routePostUnlike: wrapJSON(func(ctx context.Context, ev likeEvent) (any, error) {
			count, err := b.Like(ctx, string(ev.OwnerId), string(ev.TweetId), true)
			return event.LikesCountResponse{Count: count}, err
		}),
		routePostFollow: wrapJSON(func(ctx context.Context, ev newFollowEvent) (any, error) {
			return struct{}{}, b.Follow(ctx, string(ev.FollowerId), string(ev.FollowingId), false)
		}),
		routePostUnfollow: wrapJSON(func(ctx context.Context, ev newFollowEvent) (any, error) {
			return struct{}{}, b.Follow(ctx, string(ev.FollowerId), string(ev.FollowingId), true)
		}),
		routePostReply: wrapJSON(func(ctx context.Context, ev newReplyEvent) (any, error) {
			return replyEcho(ev), b.Reply(ctx, ev)
		}),
		// Warpnet consolidated replies into the tweet path: a reply is a tweet
		// with a parent, forwarded to the parent author's node over the private
		// tweet route (PUBLIC_POST_REPLY is no longer sent). Federate replies as
		// AP replies; a top-level owner post arrives here via follower gossip, so
		// federate it to the author's Fediverse followers in real time (the poller
		// is a slower backstop; delivery is idempotent by Create/Note id).
		routePostTweet: wrapJSON(func(ctx context.Context, ev tweet) (any, error) {
			if ev.ParentId == nil || *ev.ParentId == "" {
				if publishableTweet(ev, ev.UserId) {
					g.federateTweetAsync(ev)
				}
				return ev, nil
			}
			re := replyEventFromTweet(ev)
			return replyEcho(re), b.Reply(ctx, re)
		}),
		// Warpnet forwards a reply deletion to the parent author's node over the
		// private delete route; federate it as an AP Delete. Only a reply (a
		// parent set) targets a Mastodon note; anything else is acknowledged.
		routeDeleteTweet: wrapJSON(func(ctx context.Context, ev deleteTweetRequest) (any, error) {
			if ev.ParentId == "" && ev.RootId == "" {
				return struct{}{}, nil
			}
			return struct{}{}, b.Delete(ctx, ev)
		}),
		routePostRetweet: wrapJSON(func(ctx context.Context, ev tweet) (any, error) {
			return ev, b.Announce(ctx, retweeterOf(ev), retweetObject(ev), false)
		}),
		routePostUnretweet: wrapJSON(func(ctx context.Context, ev unretweetEvent) (any, error) {
			return struct{}{}, b.Announce(ctx, string(ev.RetweeterId), string(ev.TweetId), true)
		}),
	}

	for route, h := range handlers {
		c.h.SetStreamHandler(protocol.ID(route), c.streamHandler(route, h))
	}
	log.Infof("nodeserver: serving %d public routes as %s (owner %s)", len(handlers), c.h.ID(), ownerHandle)
}

// streamHandler reads the signed request envelope, verifies it against the
// caller's peer key (mirrors the node's auth middleware), dispatches, and writes
// the response.
func (c *nodeClient) streamHandler(route string, h routeHandler) network.StreamHandler {
	return func(s network.Stream) {
		defer func() { _ = s.Close() }()

		data, err := io.ReadAll(io.LimitReader(s, maxRequestBytes))
		if err != nil {
			log.Warnf("nodeserver: %s: read: %v", route, err)
			return
		}
		var msg message
		if uerr := wjson.Unmarshal(data, &msg); uerr != nil {
			log.Warnf("nodeserver: %s: bad envelope: %v", route, uerr)
			return
		}
		// Signature is mandatory, like the node's auth middleware: an unsigned
		// envelope must not bypass verification.
		if msg.Signature == "" {
			log.Warnf("nodeserver: %s: signature missing", route)
			return
		}
		if conn := s.Conn(); conn != nil {
			pub := warpnet.FromIDToPubKey(conn.RemotePeer())
			if verr := security.VerifySignature(pub, signingInput(msg.Body, msg.Timestamp), msg.Signature); verr != nil {
				log.Warnf("nodeserver: %s: signature from %s invalid: %v", route, conn.RemotePeer(), verr)
				return
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), apRequestTimeout)
		defer cancel()
		// Trace the whole pipeline: every outbound REST/AP fetch this libp2p
		// request fans out to is logged indented under one id, then the summary
		// line below reports the fetch count and total wall-clock.
		ctx, tr := startTrace(ctx)
		start := time.Now()
		resp, herr := h(ctx, msg.Body)
		log.Infof("[%s] libp2p %s: %d REST calls in %s", tr.id, route, tr.calls.Load(), time.Since(start).Round(time.Millisecond))
		if herr != nil {
			log.Warnf("nodeserver: %s: %v", route, herr)
			resp = event.ResponseError{Message: herr.Error()}
		}
		out, merr := wjson.Marshal(resp)
		if merr != nil {
			log.Errorf("nodeserver: %s: marshal response: %v", route, merr)
			return
		}
		if _, werr := s.Write(out); werr != nil {
			log.Warnf("nodeserver: %s: write: %v", route, werr)
		}
	}
}

// infoHandler reports the gateway as a member node owned by ownerHandle. It is
// reachable only via relays (ForceReachabilityPrivate), so it reports private
// reachability, like a NAT'd member node.
func (c *nodeClient) infoHandler(ownerHandle string) routeHandler {
	ver, _ := semver.NewVersion("0.0.0")
	networkName := envOr("NODE_NETWORK", defaultWarpnetNetwork)
	return func(context.Context, []byte) (any, error) {
		addrs := make([]string, 0, len(c.h.Addrs()))
		for _, a := range c.h.Addrs() {
			addrs = append(addrs, a.String())
		}
		return warpnet.NodeInfo{
			Type:         warpnet.MemberNode,
			OwnerId:      ownerHandle,
			ID:           c.h.ID(),
			Version:      ver,
			Addresses:    addrs,
			StartTime:    time.Now(),
			RelayState:   warpnet.RelayStatusOff,
			Reachability: warpnet.ReachabilityPrivate,
			Network:      networkName,
		}, nil
	}
}

// wrapJSON adapts a typed handler to a routeHandler by decoding the request body
// into T first.
func wrapJSON[T any](h func(context.Context, T) (any, error)) routeHandler {
	return func(ctx context.Context, body []byte) (any, error) {
		var ev T
		if len(body) > 0 {
			if err := wjson.Unmarshal(body, &ev); err != nil {
				return nil, err
			}
		}
		return h(ctx, ev)
	}
}

// replyEcho echoes a reply back as a tweet so the Warpnet UI renders it.
func replyEcho(ev newReplyEvent) tweet {
	parent := string(ev.RootId)
	if ev.ParentId != nil {
		parent = string(*ev.ParentId)
	}
	return tweet{
		Id:        string(ev.Id),
		ParentId:  &parent,
		RootId:    string(ev.RootId),
		Text:      ev.Text,
		UserId:    string(ev.UserId),
		Username:  ev.Username,
		CreatedAt: ev.CreatedAt,
		Network:   mastodonNetwork,
	}
}

// replyEventFromTweet adapts a reply forwarded over the private tweet route (a
// tweet carrying a parent) into the reply event the bridge federates. The
// parent author is derived from the parent note URL by Reply, so only the
// thread ids, author and text are needed here.
func replyEventFromTweet(ev tweet) newReplyEvent {
	re := newReplyEvent{
		CreatedAt: ev.CreatedAt,
		Id:        ev.Id,
		RootId:    ev.RootId,
		Text:      ev.Text,
		UserId:    ev.UserId,
		Username:  ev.Username,
	}
	if ev.ParentId != nil {
		pid := *ev.ParentId
		re.ParentId = &pid
	}
	return re
}

func retweeterOf(ev tweet) string {
	if ev.RetweetedBy != nil && *ev.RetweetedBy != "" {
		return *ev.RetweetedBy
	}
	return ev.UserId
}

func retweetObject(ev tweet) string {
	if ev.Id != "" {
		return ev.Id
	}
	return ev.RootId
}
