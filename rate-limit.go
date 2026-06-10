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
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	ratelimiter "github.com/filinvadim/ratelimiter"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

// Rate limiting (weighted sliding window, github.com/filinvadim/ratelimiter).
//
// Key: the remote client IP — one budget per federation peer (a Mastodon
// instance fans out from a handful of addresses), plus a global budget that
// caps total spend so many distinct IPs can't overwhelm the libp2p link to the
// member nodes, which is the scarce resource behind every expensive route.
//
// Weights price a request by what it costs the gateway, not by request count:
// nodeinfo/static are served from memory (1); webfinger and the actor document
// cost one node round-trip (2); collections and the inbox cost several
// round-trips or an outbound signature-key fetch (4); the media proxy pulls
// full image bytes through the node (8).
const (
	rateWindow = time.Minute

	// perClientBudget: weight units one client IP may spend per window
	// (~60 actor lookups, ~30 collections, or ~15 media fetches a minute).
	perClientBudget uint32 = 120
	// globalBudget bounds gateway-wide spend per window regardless of how
	// many client IPs the traffic comes from.
	globalBudget uint32 = 600

	weightStatic     uint32 = 1
	weightActor      uint32 = 2
	weightCollection uint32 = 4
	weightInbox      uint32 = 4
	weightMedia      uint32 = 8

	// Per-client limiters live in an expirable LRU: idle clients are dropped
	// after clientLimiterTTL instead of accumulating forever (statelessness —
	// the set is transient and in memory only).
	maxClientLimiters = 4096
	clientLimiterTTL  = 5 * time.Minute
)

// rateLimiters is the gateway's request throttle: one global limiter plus
// per-client-IP limiters held in an expirable LRU (evicted limiters are closed).
type rateLimiters struct {
	window       time.Duration
	clientBudget uint32
	global       *ratelimiter.Limiter

	mu      sync.Mutex // serializes get-or-create on clients
	clients *expirable.LRU[string, *ratelimiter.Limiter]
}

func newRateLimiters() *rateLimiters {
	return newRateLimitersWith(globalBudget, perClientBudget, rateWindow)
}

// newRateLimitersWith parameterizes the budgets/window so tests can exercise
// the middleware without spending 120 requests per case.
func newRateLimitersWith(global, perClient uint32, window time.Duration) *rateLimiters {
	return &rateLimiters{
		window:       window,
		clientBudget: perClient,
		global:       ratelimiter.NewLimiter(global, window, nil),
		clients: expirable.NewLRU(maxClientLimiters,
			func(_ string, l *ratelimiter.Limiter) { l.Close() },
			clientLimiterTTL),
	}
}

func (rl *rateLimiters) client(ip string) *ratelimiter.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	if l, ok := rl.clients.Get(ip); ok {
		// Get doesn't extend the entry's TTL; re-Add so eviction hits idle
		// clients only — an active client must not get a fresh budget every
		// clientLimiterTTL.
		rl.clients.Add(ip, l)
		return l
	}
	l := ratelimiter.NewLimiter(rl.clientBudget, rl.window, nil)
	rl.clients.Add(ip, l)
	return l
}

// middleware rejects requests from exhausted clients with 429 + Retry-After
// (Limit alone would sleep the handler, holding the connection); under the
// threshold it spends the route's weight, which may briefly throttle a request
// that crosses the boundary.
func (rl *rateLimiters) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lim := rl.client(clientIP(r))
		if rl.global.IsLocked() || lim.IsLocked() {
			w.Header().Set("Retry-After", strconv.Itoa(int(rl.window/time.Second)))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		weight := requestWeight(r)
		rl.global.Limit(weight, func() {
			lim.Limit(weight, func() {
				next.ServeHTTP(w, r)
			})
		})
	})
}

// clientIP keys the limiter. Tailscale Funnel's listener preserves the public
// source address, so RemoteAddr is the real client, not a proxy hop.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func requestWeight(r *http.Request) uint32 {
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, pathMedia):
		return weightMedia
	case p == pathInbox:
		return weightInbox
	case strings.HasPrefix(p, pathUsers):
		rest := strings.TrimPrefix(p, pathUsers)
		if i := strings.IndexByte(rest, '/'); i >= 0 && rest[i+1:] != "" {
			if strings.HasPrefix(rest[i+1:], "inbox") {
				return weightInbox
			}
			return weightCollection
		}
		return weightActor // actor document: one GetUser round-trip
	case strings.HasPrefix(p, "/.well-known/webfinger"):
		return weightActor // webfinger also resolves the user via the node
	}
	return weightStatic // nodeinfo, static assets
}
