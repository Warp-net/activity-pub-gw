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

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// outboundFederation lazily federates a Warpnet user's posts and follows once
// that user gains a Fediverse follower (learned from accepted inbound Follows),
// so federation follows the graph and is never pinned to a configured user.
type outboundFederation struct {
	ctx     context.Context
	req     nodeRequester
	g       *gateway
	mu      sync.Mutex
	started map[string]context.CancelFunc
}

func newOutboundFederation(ctx context.Context, req nodeRequester, g *gateway) *outboundFederation {
	return &outboundFederation{ctx: ctx, req: req, g: g, started: map[string]context.CancelFunc{}}
}

// start begins federating localUser's posts and outbound follows; idempotent per
// user, so repeated follows don't spawn duplicate pollers.
func (o *outboundFederation) start(localUser string) {
	if localUser == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.started[localUser]; ok {
		return
	}
	ctx, cancel := context.WithCancel(o.ctx)
	o.started[localUser] = cancel
	log.Infof("outbound: federating %s", localUser)
	go newTweetPoller(o.req, localUser, o.g.publishNote).run(ctx)
	go newFollowPoller(o.req, localUser,
		func(actorURL string) { o.g.sendFollow(localUser, actorURL) },
		func(actorURL string) { o.g.sendUndoFollow(localUser, actorURL) },
	).run(ctx)
	// Refresh followers' cached profile (badge, avatar, bio) once federation
	// (re)starts — e.g. after a redeploy — since Mastodon won't re-fetch the
	// actor on its own.
	go o.g.sendActorUpdate(ctx, localUser)
}

// stop cancels localUser's pollers (their last Fediverse follower is gone).
func (o *outboundFederation) stop(localUser string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	cancel, ok := o.started[localUser]
	if !ok {
		return
	}
	delete(o.started, localUser)
	cancel()
	log.Infof("outbound: stopped federating %s", localUser)
}

const followPollInterval = 30 * time.Second

// followPoller federates the owner's *outbound* follows. It polls the owner's
// followings; those that are Fediverse actors (ap:-encoded ids, i.e. accounts
// the gateway ingested) get a signed Follow delivered to their inbox, and an
// Undo(Follow) when the owner unfollows. The first poll only records a baseline
// (history isn't replayed), matching the tweet poller.
type followPoller struct {
	req        nodeRequester
	owner      string
	onFollow   func(actorURL string)
	onUnfollow func(actorURL string)
	interval   time.Duration
	known      map[string]bool // ap: actor URLs already federated; nil until first poll
}

func newFollowPoller(req nodeRequester, owner string, onFollow, onUnfollow func(string)) *followPoller {
	return &followPoller{
		req:        req,
		owner:      owner,
		onFollow:   onFollow,
		onUnfollow: onUnfollow,
		interval:   followPollInterval,
	}
}

func (p *followPoller) run(ctx context.Context) {
	t := time.NewTicker(p.interval)
	defer t.Stop()
	for {
		if err := p.poll(); err != nil {
			log.Warnf("follow poll: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// poll reads the owner's followings and fires onFollow/onUnfollow for added and
// removed Fediverse actors. The first call only seeds the baseline.
func (p *followPoller) poll() error {
	bt, err := p.req.requestUser(p.owner, routeGetFollowings, getFollowersEvent{UserId: p.owner})
	if err != nil {
		return err
	}
	var resp followingsResponse
	if err := json.Unmarshal(bt, &resp); err != nil {
		return err
	}

	current := make(map[string]bool)
	for _, id := range resp.Followings {
		if actorURL, derr := decodeActorID(id); derr == nil {
			current[actorURL] = true
		}
	}

	if p.known == nil { // baseline only — don't replay existing follows
		p.known = current
		return nil
	}
	for actorURL := range current {
		if !p.known[actorURL] {
			p.onFollow(actorURL)
		}
	}
	for actorURL := range p.known {
		if !current[actorURL] {
			p.onUnfollow(actorURL)
		}
	}
	p.known = current
	return nil
}

// sendFollow delivers a signed Follow from localUser to a remote Fediverse actor.
func (g *gateway) sendFollow(localUser, remoteActorURL string) {
	g.deliverFollow(localUser, remoteActorURL, false)
}

// sendUndoFollow delivers a signed Undo(Follow) (the owner unfollowed the actor).
func (g *gateway) sendUndoFollow(localUser, remoteActorURL string) {
	g.deliverFollow(localUser, remoteActorURL, true)
}

func (g *gateway) deliverFollow(localUser, remoteActorURL string, undo bool) {
	ctx, cancel := context.WithTimeout(context.Background(), acceptDeliveryTimeout)
	defer cancel()

	inbox, err := g.remoteInbox(ctx, remoteActorURL)
	if err != nil {
		log.Errorf("follow: resolve inbox for %s: %v", remoteActorURL, err)
		return
	}

	actorID := g.actorID(localUser)
	follow := activity{
		Context: asContext,
		ID:      actorID + "#follow-" + randomToken(),
		Type:    typeFollow,
		Actor:   actorID,
		Object:  remoteActorURL,
	}
	doc := any(follow)
	if undo {
		doc = activity{
			Context: asContext,
			ID:      actorID + "#unfollow-" + randomToken(),
			Type:    typeUndo,
			Actor:   actorID,
			Object:  follow,
		}
	}

	if err := g.postSigned(ctx, localUser, inbox, doc); err != nil {
		log.Errorf("follow: deliver to %s (undo=%v): %v", remoteActorURL, undo, err)
		return
	}
	log.Infof("follow: delivered to %s (undo=%v)", remoteActorURL, undo)
}

const (
	federationScanInterval = 5 * time.Minute
	federationScanPageSize = uint64(100)
	federationScanMaxPages = 100
)

// runScanner derives the federated set from the follow graph stored in Warpnet
// (users with at least one ap: follower) on startup and periodically, so the
// gateway persists nothing locally: federation resumes after a restart from the
// network alone, and stops when a user's last Fediverse follower unfollows.
// scanUser is the user id sent with the listing request (the node requires one).
func (o *outboundFederation) runScanner(scanUser string) {
	for {
		o.scan(scanUser)
		select {
		case <-o.ctx.Done():
			return
		case <-time.After(federationScanInterval):
		}
	}
}

// scan pages through the users known to the network and reconciles pollers with
// the ap: follower graph. Users whose follower list could not be read are left
// untouched (never stopped on a transient error).
func (o *outboundFederation) scan(scanUser string) {
	followers := nodeFollowerStore{req: o.req}
	limit := federationScanPageSize
	var cursor string
	for range federationScanMaxPages {
		ev := getAllUsersEvent{UserId: scanUser, Limit: &limit}
		if cursor != "" {
			ev.Cursor = &cursor
		}
		bt, err := o.req.request(routeGetUsers, ev)
		if err != nil {
			log.Warnf("outbound: scan users: %v", err)
			return
		}
		var resp usersResponse
		if uerr := json.Unmarshal(bt, &resp); uerr != nil {
			log.Warnf("outbound: scan users: bad response: %v", uerr)
			return
		}
		for _, u := range resp.Users {
			if u.Network == mastodonNetwork { // bridged account, lives in Mastodon already
				continue
			}
			urls, ferr := followers.List(u.Id)
			if ferr != nil {
				continue
			}
			if len(urls) > 0 {
				o.start(u.Id)
			} else {
				o.stop(u.Id)
			}
		}
		if len(resp.Users) == 0 || resp.Cursor == "" || resp.Cursor == cursor {
			return
		}
		cursor = resp.Cursor
	}
}
