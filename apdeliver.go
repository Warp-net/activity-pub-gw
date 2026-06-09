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

// apdeliver federates Warpnet actions onto Mastodon (the Warpnet -> Mastodon
// write direction): a like becomes a signed Like activity delivered to the
// author's inbox (Mastodon shows it as a favourite/star), and likewise for
// follow, reply, and boost. The acting Warpnet user is signed for as their
// gateway actor (https://host/users/<id>), which Mastodon dereferences to
// verify the HTTP signature.

import (
	"context"
	"strings"
	"time"

	"github.com/Warp-net/warpnet/domain"
)

// deliverLike sends a Like (or Undo(Like)) from localUser to the author of
// objectURL. Mastodon records it as a favourite on that status.
func (g *gateway) deliverLike(ctx context.Context, localUser, objectURL string, undo bool) error {
	objectURL = strings.TrimPrefix(objectURL, domain.RetweetPrefix)
	inbox, err := g.objectAuthorInbox(ctx, objectURL)
	if err != nil {
		return err
	}
	actorID := g.actorID(localUser)
	like := activity{
		Context: asContext,
		ID:      actorID + "#like-" + randomToken(),
		Type:    typeLike,
		Actor:   actorID,
		Object:  objectURL,
	}
	doc := any(like)
	if undo {
		doc = activity{
			Context: asContext,
			ID:      actorID + "#undo-like-" + randomToken(),
			Type:    typeUndo,
			Actor:   actorID,
			Object:  like,
		}
	}
	return g.postSigned(ctx, localUser, inbox, doc)
}

// deliverReply sends a Create(Note) reply from localUser to the author of the
// parent status.
func (g *gateway) deliverReply(ctx context.Context, ev newReplyEvent) error {
	parentURL := string(ev.RootId)
	if ev.ParentId != nil && *ev.ParentId != "" {
		parentURL = string(*ev.ParentId)
	}
	parentURL = strings.TrimPrefix(parentURL, domain.RetweetPrefix)
	inbox, err := g.objectAuthorInbox(ctx, parentURL)
	if err != nil {
		return err
	}
	localUser := string(ev.UserId)
	actorID := g.actorID(localUser)
	n := note{
		Context:      asContext,
		ID:           actorID + "/statuses/" + randomToken(),
		Type:         typeNote,
		AttributedTo: actorID,
		Content:      ev.Text,
		Published:    time.Now().UTC().Format(time.RFC3339),
		InReplyTo:    parentURL,
		To:           []string{asPublic},
	}
	create := activity{
		Context: asContext,
		ID:      n.ID + "#create",
		Type:    typeCreate,
		Actor:   actorID,
		Object:  n,
		To:      []string{asPublic},
	}
	return g.postSigned(ctx, localUser, inbox, create)
}

// deliverAnnounce sends a boost (Announce) or Undo(Announce) of objectURL from
// localUser to the boosted status's author.
func (g *gateway) deliverAnnounce(ctx context.Context, localUser, objectURL string, undo bool) error {
	objectURL = strings.TrimPrefix(objectURL, domain.RetweetPrefix)
	inbox, err := g.objectAuthorInbox(ctx, objectURL)
	if err != nil {
		return err
	}
	actorID := g.actorID(localUser)
	announce := activity{
		Context: asContext,
		ID:      actorID + "#announce-" + randomToken(),
		Type:    typeAnnounce,
		Actor:   actorID,
		Object:  objectURL,
		To:      []string{asPublic},
	}
	doc := any(announce)
	if undo {
		doc = activity{
			Context: asContext,
			ID:      actorID + "#undo-announce-" + randomToken(),
			Type:    typeUndo,
			Actor:   actorID,
			Object:  announce,
		}
	}
	return g.postSigned(ctx, localUser, inbox, doc)
}
