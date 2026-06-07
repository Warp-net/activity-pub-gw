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

	"github.com/Masterminds/semver/v3"
	camouflage "github.com/Warp-net/libp2p-camouflage-transport"
	"github.com/Warp-net/warpnet/security"
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

// nodeClient joins the Warpnet DHT through the network's relays and streams the
// /public/... routes to the member nodes it discovers via the DHT.
type nodeClient struct {
	h      host.Host
	priv   ed25519.PrivateKey
	dht    *dht.IpfsDHT
	relays map[peer.ID]struct{} // entry peers (relays): discovery/connectivity only, not data routes

	mu   sync.Mutex
	good []peer.ID // member nodes known to answer data routes; tried first
}

// networkEntries are the network's bootstrap relays (the DHT entry points) plus
// an optional explicit GATEWAY_NODE_ADDR.
func networkEntries(network string) ([]peer.AddrInfo, error) {
	var entries []peer.AddrInfo
	for _, s := range bootstrapByNetwork[network] {
		ai, err := peer.AddrInfoFromString(s)
		if err != nil {
			log.Warnf("nodeclient: bad bootstrap %q: %v", s, err)
			continue
		}
		entries = append(entries, *ai)
	}
	if extra := envOr("GATEWAY_NODE_ADDR", ""); extra != "" {
		ai, err := peer.AddrInfoFromString(extra)
		if err != nil {
			return nil, fmt.Errorf("bad GATEWAY_NODE_ADDR: %w", err)
		}
		entries = append(entries, *ai)
	}
	if len(entries) == 0 {
		return nil, errNoEntryPeers
	}
	return entries, nil
}

// connectNetwork builds a libp2p host wired for Warpnet and joins through the
// configured network's entry peers.
func connectNetwork(ctx context.Context) (*nodeClient, error) {
	network := envOr("NODE_NETWORK", defaultWarpnetNetwork)
	entries, err := networkEntries(network)
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

	// PSK keys the private network on the network name + MAJOR version (warpnet's
	// security.GeneratePSK); major 0 matches the live networks.
	ver, err := semver.NewVersion("0.0.0")
	if err != nil {
		return nil, fmt.Errorf("nodeclient: version: %w", err)
	}
	psk, err := security.GeneratePSK(network, ver)
	if err != nil {
		return nil, fmt.Errorf("nodeclient: psk: %w", err)
	}

	h, err := libp2p.New(
		libp2p.Identity(p2pPriv),
		libp2p.PrivateNetwork(pnet.PSK(psk)),
		libp2p.ListenAddrStrings("/ip4/0.0.0.0/tcp/0"),
		libp2p.WithDialTimeout(60*time.Second),
		libp2p.Transport(camouflage.NewCamouflageTransport),
		libp2p.Ping(true),
		libp2p.Security(noise.ID, noise.New),
		// Outbound-only client (inbound is via Tailscale Funnel): advertise NO
		// AutoNAT/NAT services. EnableNATService made this NAT'd peer answer other
		// nodes' reachability probes with wrong verdicts, flipping public member
		// nodes to "private" (crashing business nodes). Only the relay transport
		// is needed — to dial member nodes that are reachable via a relay.
		libp2p.EnableRelay(),
	)
	if err != nil {
		return nil, fmt.Errorf("nodeclient: new host: %w", err)
	}

	// Join Warpnet's Kademlia DHT (prefix "/<network>", bootstrapped via the relays).
	kdht, err := dht.New(ctx, h,
		dht.Mode(dht.ModeClient),
		dht.ProtocolPrefix(protocol.ID("/"+network)),
		dht.BootstrapPeers(entries...),
	)
	if err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("nodeclient: dht: %w", err)
	}

	relays := make(map[peer.ID]struct{}, len(entries))
	var connected int
	for _, e := range entries {
		relays[e.ID] = struct{}{}
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
	select {
	case <-kdht.RefreshRoutingTable():
	case <-time.After(20 * time.Second):
	case <-ctx.Done():
	}
	log.Infof("nodeclient: joined Warpnet (%s) via %d relay(s); discovering members via DHT", network, connected)

	return &nodeClient{h: h, priv: priv, dht: kdht, relays: relays}, nil
}

// request streams the route to the member nodes discovered via the DHT, trying
// each until one answers (relays serve only discovery, so they are excluded).
func (c *nodeClient) request(route string, payload any) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	peers := c.memberCandidates()
	if len(peers) == 0 && c.dht != nil {
		select { // routing table not populated yet — refresh and retry
		case <-c.dht.RefreshRoutingTable():
		case <-time.After(15 * time.Second):
		case <-ctx.Done():
		}
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
		Avatar:            u.AvatarKey,
		Background:        u.BackgroundImageKey,
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
