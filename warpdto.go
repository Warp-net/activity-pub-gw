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

// The gateway's wire contract is now warpnet's own: route protocol IDs come
// from event.PUBLIC_*, and payloads/responses are warpnet's event/domain types
// (aliased to the gateway's local names so call sites stay terse). domain.ID is
// a string alias, so these are byte-for-byte the shapes the node speaks.

import (
	"github.com/Warp-net/warpnet/domain"
	"github.com/Warp-net/warpnet/event"
)

// Public-route protocol IDs (each is also the libp2p protocol string).
const (
	routeGetUser       = event.PUBLIC_GET_USER
	routeGetUsers      = event.PUBLIC_GET_USERS
	routeGetTweet      = event.PUBLIC_GET_TWEET
	routeGetTweets     = event.PUBLIC_GET_TWEETS
	routeGetReplies    = event.PUBLIC_GET_REPLIES
	routeGetFollowers  = event.PUBLIC_GET_FOLLOWERS
	routeGetFollowings = event.PUBLIC_GET_FOLLOWINGS
	routeGetImage      = event.PUBLIC_GET_IMAGE
	routePostFollow    = event.PUBLIC_POST_FOLLOW
	routePostUnfollow  = event.PUBLIC_POST_UNFOLLOW
	routePostLike      = event.PUBLIC_POST_LIKE
	routePostUnlike    = event.PUBLIC_POST_UNLIKE
	routePostRetweet   = event.PUBLIC_POST_RETWEET
	routePostUnretweet = event.PUBLIC_POST_UNRETWEET
	routePostReply     = event.PUBLIC_POST_REPLY
	// routePostTweet is the route warpnet forwards replies over after it
	// consolidated replies into the tweet path (a reply is a tweet with a
	// parent); it superseded the standalone PUBLIC_POST_REPLY route.
	routePostTweet = event.PRIVATE_POST_TWEET
	// routeDeleteTweet is the route warpnet forwards a reply deletion over to
	// the parent author's node.
	routeDeleteTweet = event.PRIVATE_DELETE_TWEET
)

// Wire envelope + domain payloads (warpnet's own types).
type (
	message = event.Message
	tweet   = domain.Tweet
	user    = domain.User
)

// Request/response event payloads (warpnet's own types).
type (
	getUserEvent       = event.GetUserEvent
	getAllUsersEvent   = event.GetAllUsersEvent
	usersResponse      = event.UsersResponse
	getTweetEvent      = event.GetTweetEvent
	getRepliesEvent    = event.GetAllRepliesEvent
	getAllTweetsEvent  = event.GetAllTweetsEvent
	tweetsResponse     = event.TweetsResponse
	repliesResponse    = event.RepliesResponse
	getFollowersEvent  = event.GetAllTweetsEvent // {user_id, cursor}; same shape for followers/followings
	followersResponse  = event.FollowersResponse
	followingsResponse = event.FollowingsResponse
	newFollowEvent     = event.NewFollowEvent
	likeEvent          = event.LikeEvent
	unretweetEvent     = event.UnretweetEvent
	newReplyEvent      = event.NewReplyEvent
	getImageEvent      = event.GetImageEvent
	getImageResponse   = event.GetImageResponse
)

// getTweetsRequest is the PUBLIC_GET_TWEETS body. Warpnet folded thread replies
// into this route (a profile request carries only user_id; a thread-replies
// request carries root_id/parent_id), but the pinned event.GetAllTweetsEvent
// predates the reply fields, so decode them here to dispatch on them.
type getTweetsRequest struct {
	UserId   string  `json:"user_id"`
	RootId   string  `json:"root_id"`
	ParentId string  `json:"parent_id"`
	Cursor   *string `json:"cursor,omitempty"`
}

// deleteTweetRequest is the PRIVATE_DELETE_TWEET body warpnet forwards for a
// reply deletion. The pinned event.DeleteTweetEvent (= GetTweetEvent) predates
// the thread ids, so decode parent_id/root_id here to locate the parent note.
type deleteTweetRequest struct {
	UserId   string `json:"user_id"`
	TweetId  string `json:"tweet_id"`
	ParentId string `json:"parent_id"`
	RootId   string `json:"root_id"`
}
