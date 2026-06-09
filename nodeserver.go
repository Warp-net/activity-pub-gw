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

// nodeserver makes the gateway answer Warpnet's public /public/... routes over
// libp2p (the Mastodon -> Warpnet direction). To a Warpnet node the gateway is
// an ordinary member peer: it reports node info with a hardcoded owner (a
// Mastodon account), so discovery seeds that account, and resolves every
// user/tweet/image request live from the Fediverse via ActivityPub. The gateway
// keeps no Warpnet user of its own. It does NOT register the spoof challenge
// route — it isn't a Warpnet-codebase node — which the node tolerates
// (discovery's challenge is non-fatal).

import (
	"context"
	"encoding/json"
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

// maxRequestBytes bounds an inbound request envelope (the response we write
// back, e.g. an image, is not capped here).
const maxRequestBytes = 1 << 20

// apRequestTimeout bounds the ActivityPub work done to answer one node request.
const apRequestTimeout = 30 * time.Second

// routeHandler answers one public route from the signed request body.
type routeHandler func(ctx context.Context, body []byte) (any, error)

// serveRoutes registers the gateway as a libp2p server for Warpnet's public
// routes. ownerHandle is the Mastodon account (name@instance) the gateway
// advertises as its node owner so discovery seeds it.
func (c *nodeClient) serveRoutes(g *gateway, ownerHandle string) {
	g.nodeID = c.h.ID().String()

	handlers := map[string]routeHandler{
		event.PUBLIC_GET_INFO:        c.infoHandler(ownerHandle),
		routeGetUser:                 wrapJSON(g.handleGetUser),
		event.PUBLIC_GET_USERS:       wrapJSON(g.handleGetUsers),
		routeGetTweets:               wrapJSON(g.handleGetTweets),
		routeGetTweet:                wrapJSON(g.handleGetTweet),
		routeGetReplies:              wrapJSON(g.handleGetReplies),
		routeGetFollowers:            wrapJSON(g.handleGetFollowers),
		routeGetFollowings:           wrapJSON(g.handleGetFollowings),
		routeGetImage:                wrapJSON(g.handleGetImage),
		event.PUBLIC_GET_TWEET_STATS: wrapJSON(g.handleGetTweetStats),
		event.PUBLIC_POST_VIEW:       func(context.Context, []byte) (any, error) { return event.ViewsCountResponse{Count: 1}, nil },
		// Write routes federate the Warpnet action onto Mastodon as a signed
		// ActivityPub activity (Mastodon -> star/boost/reply/follow).
		routePostLike:      wrapJSON(g.handleLike),
		routePostUnlike:    wrapJSON(g.handleUnlike),
		routePostFollow:    wrapJSON(g.handleFollow),
		routePostUnfollow:  wrapJSON(g.handleUnfollow),
		routePostReply:     wrapJSON(g.handleReply),
		routePostRetweet:   wrapJSON(g.handleRetweet),
		routePostUnretweet: wrapJSON(g.handleUnretweet),
	}

	for route, h := range handlers {
		c.h.SetStreamHandler(protocol.ID(route), c.streamHandler(route, h))
	}
	log.Infof("nodeserver: serving %d public routes as %s (owner %s)", len(handlers), g.nodeID, ownerHandle)
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
		if conn := s.Conn(); conn != nil && msg.Signature != "" {
			pub := warpnet.FromIDToPubKey(conn.RemotePeer())
			if verr := security.VerifySignature(pub, msg.Body, msg.Signature); verr != nil {
				log.Warnf("nodeserver: %s: signature from %s invalid: %v", route, conn.RemotePeer(), verr)
				return
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), apRequestTimeout)
		defer cancel()
		resp, herr := h(ctx, msg.Body)
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

// infoHandler reports the gateway as a public member node owned by ownerHandle.
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
			Reachability: warpnet.ReachabilityPublic,
			Network:      networkName,
		}, nil
	}
}

func (g *gateway) handleGetUser(ctx context.Context, ev getUserEvent) (any, error) {
	return g.apGetUser(ctx, ev.UserId)
}

// handleGetUsers returns just the requested user; the gateway does not enumerate
// the Fediverse.
func (g *gateway) handleGetUsers(ctx context.Context, ev getAllTweetsEvent) (any, error) {
	u, err := g.apGetUser(ctx, ev.UserId)
	if err != nil {
		return event.UsersResponse{}, nil //nolint:nilerr // unknown handle -> empty, not an error
	}
	return event.UsersResponse{Users: []user{u}}, nil
}

func (g *gateway) handleGetTweets(ctx context.Context, ev getAllTweetsEvent) (any, error) {
	return g.apGetTweets(ctx, ev.UserId, ev.Cursor)
}

func (g *gateway) handleGetTweet(ctx context.Context, ev getTweetEvent) (any, error) {
	return g.apGetTweet(ctx, ev.TweetId)
}

func (g *gateway) handleGetReplies(ctx context.Context, ev getTweetEvent) (any, error) {
	return g.apGetReplies(ctx, ev.TweetId)
}

// handleGetTweetStats reads the like/boost/reply counts Mastodon publishes on
// the Note's likes/shares/replies collections.
func (g *gateway) handleGetTweetStats(ctx context.Context, ev getTweetEvent) (any, error) {
	return g.apGetTweetStats(ctx, ev.TweetId)
}

func (g *gateway) handleGetFollowers(ctx context.Context, ev getFollowersEvent) (any, error) {
	return g.apGetFollowers(ctx, ev.UserId, ev.Cursor)
}

func (g *gateway) handleGetFollowings(ctx context.Context, ev getFollowersEvent) (any, error) {
	return g.apGetFollowings(ctx, ev.UserId, ev.Cursor)
}

func (g *gateway) handleGetImage(ctx context.Context, ev getImageEvent) (any, error) {
	return g.apGetImage(ctx, ev.Key)
}

// handleLike federates a Warpnet like onto Mastodon as a Like activity
// (Mastodon shows it as a favourite/star) and reports the status's like count.
func (g *gateway) handleLike(ctx context.Context, ev likeEvent) (any, error) {
	if err := g.deliverLike(ctx, string(ev.UserId), string(ev.TweetId), false); err != nil {
		return nil, err
	}
	stats, _ := g.apGetTweetStats(ctx, string(ev.TweetId))
	return event.LikesCountResponse{Count: stats.LikeCount}, nil
}

func (g *gateway) handleUnlike(ctx context.Context, ev likeEvent) (any, error) {
	if err := g.deliverLike(ctx, string(ev.UserId), string(ev.TweetId), true); err != nil {
		return nil, err
	}
	stats, _ := g.apGetTweetStats(ctx, string(ev.TweetId))
	return event.LikesCountResponse{Count: stats.LikeCount}, nil
}

func (g *gateway) handleFollow(ctx context.Context, ev newFollowEvent) (any, error) {
	actorURL, err := g.apResolveHandle(ctx, string(ev.FollowingId))
	if err != nil {
		return nil, err
	}
	g.deliverFollow(string(ev.FollowerId), actorURL, false)
	return struct{}{}, nil
}

func (g *gateway) handleUnfollow(ctx context.Context, ev newFollowEvent) (any, error) {
	actorURL, err := g.apResolveHandle(ctx, string(ev.FollowingId))
	if err != nil {
		return nil, err
	}
	g.deliverFollow(string(ev.FollowerId), actorURL, true)
	return struct{}{}, nil
}

// handleReply federates a Warpnet reply as a Create(Note) inReplyTo the Mastodon
// status, and echoes the reply back so the Warpnet UI renders it.
func (g *gateway) handleReply(ctx context.Context, ev newReplyEvent) (any, error) {
	if err := g.deliverReply(ctx, ev); err != nil {
		return nil, err
	}
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
	}, nil
}

func (g *gateway) handleRetweet(ctx context.Context, ev tweet) (any, error) {
	retweeter := ev.UserId
	if ev.RetweetedBy != nil && *ev.RetweetedBy != "" {
		retweeter = *ev.RetweetedBy
	}
	object := ev.Id
	if object == "" {
		object = ev.RootId
	}
	if err := g.deliverAnnounce(ctx, retweeter, object, false); err != nil {
		return nil, err
	}
	return ev, nil
}

func (g *gateway) handleUnretweet(ctx context.Context, ev unretweetEvent) (any, error) {
	if err := g.deliverAnnounce(ctx, string(ev.RetweeterId), string(ev.TweetId), true); err != nil {
		return nil, err
	}
	return struct{}{}, nil
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

// decodeJSONObject parses bytes into a JSON object, used by apsource for AP docs.
func decodeJSONObject(bt []byte) (map[string]any, error) {
	var m map[string]any
	if err := json.Unmarshal(bt, &m); err != nil {
		return nil, err
	}
	return m, nil
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
