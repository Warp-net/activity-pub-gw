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

// DHT-based discovery of Warpnet member/moderator nodes. The gateway joins the
// network's Kademlia DHT through the relays (nodeclient.go) but the relays only
// answer discovery — the /public/... data routes live on member/moderator
// nodes. This finds those nodes (via the DHT routing table and the same
// rendezvous namespace Warpnet nodes use) so request() can stream to them.

import (
	"context"
	"time"

	"github.com/libp2p/go-libp2p/core/discovery"
	"github.com/libp2p/go-libp2p/core/peer"
	drouting "github.com/libp2p/go-libp2p/p2p/discovery/routing"
	log "github.com/sirupsen/logrus"
)

const maxMemberCandidates = 64

// rendezvousNamespace mirrors Warpnet's DHT rendezvous namespace (core/dht).
func rendezvousNamespace(network string) string {
	return "warpnet/rendezvous/" + network
}

// runDiscovery keeps pulling member nodes out of the DHT in the background
// (mirrors the node's rendezvous loop), so request() usually has candidates
// ready without an on-demand lookup.
func (c *nodeClient) runDiscovery(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	c.discoverMembers(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.discoverMembers(ctx)
		}
	}
}

// discoverMembers asks the DHT for providers of the Warpnet rendezvous
// namespace and caches their addresses. It is best-effort: request() also falls
// back to the DHT routing-table peers, so this is harmless when the namespace
// has no providers.
func (c *nodeClient) discoverMembers(ctx context.Context) {
	if c.dht == nil {
		return
	}
	rd := drouting.NewRoutingDiscovery(c.dht)
	fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ch, err := rd.FindPeers(fctx, rendezvousNamespace(c.network), discovery.Limit(50))
	if err != nil {
		log.Debugf("nodeclient: discover: %v", err)
		return
	}
	for pi := range ch {
		if pi.ID == c.h.ID() || len(pi.Addrs) == 0 {
			continue
		}
		c.h.Peerstore().AddAddrs(pi.ID, pi.Addrs, time.Hour)
	}
}

// memberCandidates lists peers that may serve the public data routes: members
// known to have answered before (first), then the DHT routing-table peers
// (Warpnet member/moderator nodes are DHT servers). The relay entry peers are
// excluded — they only handle discovery.
func (c *nodeClient) memberCandidates() []peer.ID {
	seen := make(map[peer.ID]struct{})
	out := make([]peer.ID, 0, maxMemberCandidates)
	add := func(p peer.ID) {
		if p == "" || p == c.h.ID() {
			return
		}
		if _, ok := c.relays[p]; ok {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	c.mu.Lock()
	for _, p := range c.good {
		add(p)
	}
	c.mu.Unlock()

	if c.dht != nil {
		for _, p := range c.dht.RoutingTable().ListPeers() {
			add(p)
		}
	}
	if len(out) > maxMemberCandidates {
		out = out[:maxMemberCandidates]
	}
	return out
}

// streamToMember makes sure the peer's addresses are known (resolving them via
// the DHT if needed) and then sends the signed request.
func (c *nodeClient) streamToMember(ctx context.Context, p peer.ID, route string, payload any) ([]byte, error) {
	if len(c.h.Peerstore().Addrs(p)) == 0 && c.dht != nil {
		fctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		if pi, err := c.dht.FindPeer(fctx, p); err == nil {
			c.h.Peerstore().AddAddrs(p, pi.Addrs, time.Hour)
		}
		cancel()
	}
	return streamSend(ctx, c.h, p, c.priv, route, payload)
}

// remember moves a member that answered to the front of the cache so later
// requests try it first.
func (c *nodeClient) remember(p peer.ID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]peer.ID, 0, len(c.good)+1)
	out = append(out, p)
	for _, q := range c.good {
		if q != p {
			out = append(out, q)
		}
	}
	if len(out) > maxMemberCandidates {
		out = out[:maxMemberCandidates]
	}
	c.good = out
}
