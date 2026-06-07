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
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	camouflage "github.com/Warp-net/libp2p-camouflage-transport"
	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/pnet"
	"github.com/libp2p/go-libp2p/core/protocol"
	noise "github.com/libp2p/go-libp2p/p2p/security/noise"
	log "github.com/sirupsen/logrus"
)

var (
	errNoEntryPeers     = errors.New("no Warpnet entry peers (set NODE_NETWORK or GATEWAY_NODE_ADDR)")
	errNoEntryReachable = errors.New("nodeclient: no Warpnet entry peer reachable")
)

// nodeClient is the gateway's libp2p connection into the Warpnet network. It
// joins the same Kademlia DHT as Warpnet nodes (warpnet's PSK / camouflage
// transport / noise), bootstrapping through the network's relays. The relays
// only answer discovery (PUBLIC_GET_INFO), so the gateway resolves the
// member/moderator nodes that serve the /public/... data routes via the DHT and
// streams requests to them. It is agnostic to any specific node and stores no
// node/profile state.
type nodeClient struct {
	h       host.Host
	priv    ed25519.PrivateKey
	dht     *dht.IpfsDHT
	network string
	relays  map[peer.ID]struct{} // entry peers (relays): discovery/connectivity only, not data routes

	mu   sync.Mutex
	good []peer.ID // member nodes known to answer data routes; tried first
}

// networkEntries are the peers the gateway uses to enter Warpnet: the network's
// bootstrap relays (for DHT bootstrap + connectivity) plus an optional explicit
// GATEWAY_NODE_ADDR. It also returns the set of relay IDs: relays only answer
// discovery, so they are excluded as data-route targets — member nodes are
// found via the DHT, and GATEWAY_NODE_ADDR (not a relay) is treated as a known
// member hint.
func networkEntries(network string) ([]peer.AddrInfo, map[peer.ID]struct{}, error) {
	var entries []peer.AddrInfo
	relays := make(map[peer.ID]struct{})
	for _, s := range bootstrapByNetwork[network] {
		ai, err := peer.AddrInfoFromString(s)
		if err != nil {
			log.Warnf("nodeclient: bad bootstrap %q: %v", s, err)
			continue
		}
		entries = append(entries, *ai)
		relays[ai.ID] = struct{}{}
	}
	if extra := envOr("GATEWAY_NODE_ADDR", ""); extra != "" {
		ai, err := peer.AddrInfoFromString(extra)
		if err != nil {
			return nil, nil, fmt.Errorf("bad GATEWAY_NODE_ADDR: %w", err)
		}
		entries = append(entries, *ai) // a member hint, not a relay
	}
	if len(entries) == 0 {
		return nil, nil, errNoEntryPeers
	}
	return entries, relays, nil
}

// connectNetwork builds a libp2p host wired for Warpnet and joins through the
// configured network's entry peers.
func connectNetwork(ctx context.Context) (*nodeClient, error) {
	network := envOr("NODE_NETWORK", defaultWarpnetNetwork)
	entries, relays, err := networkEntries(network)
	if err != nil {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("nodeclient: identity: %w", err)
	}
	p2pPriv, err := p2pcrypto.UnmarshalEd25519PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("nodeclient: key: %w", err)
	}

	h, err := libp2p.New(
		libp2p.Identity(p2pPriv),
		libp2p.PrivateNetwork(pnet.PSK(generatePSK(network))),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
		libp2p.WithDialTimeout(60*time.Second),
		libp2p.Transport(camouflage.NewCamouflageTransport),
		libp2p.Ping(true),
		libp2p.Security(noise.ID, noise.New),
		libp2p.EnableAutoNATv2(),
		libp2p.EnableRelay(),
		libp2p.EnableHolePunching(),
		libp2p.EnableNATService(),
		libp2p.NATPortMap(),
	)
	if err != nil {
		return nil, fmt.Errorf("nodeclient: new host: %w", err)
	}

	// Join the same Kademlia DHT as Warpnet nodes: protocol prefix "/<network>"
	// and bootstrapped via the entry peers (relays). This is what lets the
	// gateway discover the member/moderator nodes that serve /public/... — the
	// relays themselves only handle discovery.
	kdht, err := dht.New(ctx, h,
		dht.Mode(dht.ModeClient),
		dht.ProtocolPrefix(protocol.ID("/"+network)),
		dht.BootstrapPeers(entries...),
	)
	if err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("nodeclient: dht: %w", err)
	}

	var connected int
	for _, e := range entries {
		if cerr := h.Connect(ctx, e); cerr != nil {
			log.Warnf("nodeclient: connect %s: %v", e.ID, cerr)
			continue
		}
		connected++
	}
	if connected == 0 {
		_ = kdht.Close()
		_ = h.Close()
		return nil, errNoEntryReachable
	}

	if berr := kdht.Bootstrap(ctx); berr != nil {
		log.Warnf("nodeclient: dht bootstrap: %v", berr)
	}
	// Let the routing table fill with member/moderator nodes before serving.
	select {
	case <-kdht.RefreshRoutingTable():
	case <-time.After(20 * time.Second):
	case <-ctx.Done():
	}
	log.Infof("nodeclient: joined Warpnet (%s) via %d relay(s); discovering member nodes via DHT", network, connected)

	c := &nodeClient{h: h, priv: priv, dht: kdht, network: network, relays: relays}
	// Seed any explicit GATEWAY_NODE_ADDR (a non-relay entry) as a known member.
	for _, e := range entries {
		if _, isRelay := relays[e.ID]; !isRelay {
			c.good = append(c.good, e.ID)
		}
	}
	go c.runDiscovery(ctx)
	return c, nil
}

// request streams the route to discovered Warpnet member/moderator nodes (the
// peers that serve /public/...), trying each until one answers. Relays are
// excluded — they only handle discovery. Members are found via the DHT.
func (c *nodeClient) request(route string, payload any) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	peers := c.memberCandidates()
	if len(peers) == 0 {
		c.discoverMembers(ctx) // on-demand: routing table not populated yet
		peers = c.memberCandidates()
	}
	if len(peers) == 0 {
		return nil, fmt.Errorf("nodeclient: %s: no Warpnet member nodes discovered yet", route)
	}

	var lastErr error
	for _, p := range peers {
		bt, err := c.streamToMember(ctx, p, route, payload)
		if err == nil {
			c.remember(p)
			return bt, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("nodeclient: %s failed on all member nodes: %w", route, lastErr)
}

func (c *nodeClient) close() {
	if c == nil {
		return
	}
	if c.dht != nil {
		_ = c.dht.Close()
	}
	if c.h != nil {
		_ = c.h.Close()
	}
}

// nodeSource reads any requested user's profile live from the Warpnet network
// via the user route, so the gateway is agnostic to which user it serves and
// stores no profile of its own.
type nodeSource struct {
	client *nodeClient
}

func (s nodeSource) GetUser(preferredUsername string) (warpnetUser, bool) {
	bt, err := s.client.request(routeGetUser, getUserEvent{UserId: preferredUsername})
	if err != nil {
		log.Errorf("nodesource: get user %s: %v", preferredUsername, err)
		return warpnetUser{}, false
	}
	var u user
	if uerr := json.Unmarshal(bt, &u); uerr != nil || u.Id == "" {
		return warpnetUser{}, false
	}
	return warpnetUser{
		ID:                u.Id,
		PreferredUsername: u.Id,
		DisplayName:       u.Username,
		Summary:           u.Bio,
	}, true
}

// runProbe joins Warpnet and fetches the GATEWAY_USER profile — a smoke test of
// the connector path.
func runProbe() {
	u := envOr("GATEWAY_USER", "")
	if u == "" {
		log.Errorln("probe: set GATEWAY_USER (and optionally GATEWAY_NODE_ADDR)")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cl, err := connectNetwork(ctx)
	if err != nil {
		log.Errorf("probe: connect: %v", err)
		return
	}
	defer cl.close()

	wu, ok := nodeSource{client: cl}.GetUser(u)
	if !ok {
		log.Errorln("probe: user not found / unreadable")
		return
	}
	log.Infof("probe: OK — user id=%s name=%q bio=%q", wu.ID, wu.DisplayName, wu.Summary)
}
