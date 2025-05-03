package policyeval

import (
	"context"
	"slices"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exzerolog"
	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policylist"
	"go.mau.fi/meowlnir/util"
)

type pendingInvite struct {
	Inviter id.UserID
	Invitee id.UserID
	Room    id.RoomID
}

func (pe *PolicyEvaluator) HandleUserMayInvite(ctx context.Context, inviter, invitee id.UserID, roomID id.RoomID) *mautrix.RespError {
	inviterServer := inviter.Homeserver()
	// We only care about federated invites.
	if inviterServer == pe.Bot.ServerName && !pe.FilterLocalInvites {
		return nil
	}

	log := zerolog.Ctx(ctx).With().
		Stringer("inviter", inviter).
		Stringer("invitee", invitee).
		Stringer("room_id", roomID).
		Logger()
	if invitee.Homeserver() != pe.Bot.ServerName {
		// This shouldn't happen
		// TODO this check should be removed if multi-server support is added
		log.Warn().Msg("Ignoring invite to non-local user")
		return nil
	}
	lists := pe.GetWatchedLists()

	var rec *policylist.Policy

	defer func() {
		if rec != nil {
			go pe.sendNotice(
				context.WithoutCancel(ctx),
				"Blocked [%s](%s) from inviting [%s](%s) to [%s](%s) due to policy banning `%s` for `%s`",
				inviter, inviter.URI().MatrixToURL(),
				invitee, invitee.URI().MatrixToURL(),
				roomID, roomID.URI().MatrixToURL(),
				rec.EntityOrHash(), rec.Reason,
			)
		}
	}()

	if rec = pe.Store.MatchUser(lists, inviter).Recommendations().BanOrUnban; rec != nil && rec.Recommendation != event.PolicyRecommendationUnban {
		log.Debug().
			Str("policy_entity", rec.EntityOrHash()).
			Str("policy_reason", rec.Reason).
			Msg("Blocking invite from banned user")
		return ptr.Ptr(mautrix.MForbidden.WithMessage("You're not allowed to send invites"))
	}

	if rec = pe.Store.MatchRoom(lists, roomID).Recommendations().BanOrUnban; rec != nil && rec.Recommendation != event.PolicyRecommendationUnban {
		log.Debug().
			Str("policy_entity", rec.EntityOrHash()).
			Str("policy_reason", rec.Reason).
			Msg("Blocking invite to banned room")
		return ptr.Ptr(mautrix.MForbidden.WithMessage("Inviting users to this room is not allowed"))
	}

	if rec = pe.Store.MatchServer(lists, inviterServer).Recommendations().BanOrUnban; rec != nil && rec.Recommendation != event.PolicyRecommendationUnban {
		log.Debug().
			Str("policy_entity", rec.EntityOrHash()).
			Str("policy_reason", rec.Reason).
			Msg("Blocking invite from banned server")
		return ptr.Ptr(mautrix.MForbidden.WithMessage("You're not allowed to send invites"))
	}

	// Parsing room IDs is generally not allowed, but in this case,
	// if a room was created on a banned server, there's no reason to allow invites to it.
	_, _, roomServer := id.ParseCommonIdentifier(roomID)
	if rec = pe.Store.MatchServer(lists, roomServer).Recommendations().BanOrUnban; rec != nil && rec.Recommendation != event.PolicyRecommendationUnban {
		log.Debug().
			Str("policy_entity", rec.EntityOrHash()).
			Str("policy_reason", rec.Reason).
			Msg("Blocking invite to room on banned server")
		return ptr.Ptr(mautrix.MForbidden.WithMessage("Inviting users to this room is not allowed"))
	}

	rec = nil
	log.Debug().Msg("Allowing invite")

	if pe.AutoRejectInvites {
		pe.pendingInvitesLock.Lock()
		pe.pendingInvites[pendingInvite{Inviter: inviter, Invitee: invitee, Room: roomID}] = struct{}{}
		pe.pendingInvitesLock.Unlock()

		pe.protectedRoomsLock.Lock()
		_, trackingMember := pe.protectedRoomMembers[inviter]
		if !trackingMember {
			// Add the inviter to the list of tracked members so that new policy evaluation
			// will catch them and call RejectPendingInvites.
			pe.protectedRoomMembers[inviter] = []id.RoomID{}
			pe.memberHashes[util.SHA256String(string(inviter))] = inviter
		}
		pe.protectedRoomsLock.Unlock()
	}

	return nil
}

func (pe *PolicyEvaluator) HandleAcceptMakeJoin(ctx context.Context, roomID id.RoomID, userID id.UserID) *mautrix.RespError {
	lists := pe.GetWatchedLists()
	rec := pe.Store.MatchUser(lists, userID).Recommendations().BanOrUnban
	if rec == nil {
		rec = pe.Store.MatchServer(lists, userID.Homeserver()).Recommendations().BanOrUnban
	}
	if rec != nil && rec.Recommendation != event.PolicyRecommendationUnban {
		zerolog.Ctx(ctx).Debug().
			Stringer("user_id", userID).
			Stringer("room_id", roomID).
			Str("policy_entity", rec.EntityOrHash()).
			Str("policy_reason", rec.Reason).
			Msg("Blocking restricted join from banned user")
		go pe.sendNotice(
			context.WithoutCancel(ctx),
			"Blocked [%s](%s) from joining [%s](%s) due to policy banning `%s` for `%s`",
			userID, userID.URI().MatrixToURL(),
			roomID, roomID.URI().MatrixToURL(),
			rec.EntityOrHash(), rec.Reason,
		)
		return ptr.Ptr(mautrix.MForbidden.WithMessage("You're banned from this room"))
	}

	zerolog.Ctx(ctx).Debug().
		Stringer("user_id", userID).
		Stringer("room_id", roomID).
		Msg("Allowing restricted join")
	return nil
}

func (pe *PolicyEvaluator) HandleUserMayJoinRoom(ctx context.Context, userID id.UserID, roomID id.RoomID, isInvited bool) {
	if !pe.AutoRejectInvites {
		return
	}
	pe.pendingInvitesLock.Lock()
	defer pe.pendingInvitesLock.Unlock()
	wasInvite := false
	var inviter id.UserID
	for invite := range pe.pendingInvites {
		if invite.Invitee == userID && invite.Room == roomID {
			delete(pe.pendingInvites, invite)
			wasInvite = true
			inviter = invite.Inviter
		}
	}
	if !wasInvite {
		return
	}
	zerolog.Ctx(ctx).Debug().
		Stringer("user_id", userID).
		Stringer("room_id", roomID).
		Stringer("inviter", inviter).
		Bool("is_invited", isInvited).
		Msg("User accepted pending invite")
}

func (pe *PolicyEvaluator) findPendingInvites(userID id.UserID) map[id.UserID][]id.RoomID {
	pe.pendingInvitesLock.Lock()
	defer pe.pendingInvitesLock.Unlock()
	output := make(map[id.UserID][]id.RoomID)
	for invite := range pe.pendingInvites {
		if invite.Inviter == userID {
			output[invite.Invitee] = append(output[invite.Invitee], invite.Room)
			delete(pe.pendingInvites, invite)
		}
	}
	return output
}

func (pe *PolicyEvaluator) RejectPendingInvites(ctx context.Context, inviter id.UserID, rec *policylist.Policy) {
	if !pe.AutoRejectInvites {
		return
	}
	log := zerolog.Ctx(ctx)
	invites := pe.findPendingInvites(inviter)
	for userID, rooms := range invites {
		log.Debug().
			Stringer("inviter_user_id", inviter).
			Stringer("invited_user_id", userID).
			Array("room_ids", exzerolog.ArrayOfStrs(rooms)).
			Msg("Rejecting pending invites")
		client := pe.createPuppetClient(userID)
		resp, err := client.JoinedRooms(ctx)
		if err != nil {
			log.Err(err).Msg("Failed to get joined rooms to ensure accepted invites aren't rejected")
		}
		successfullyRejected := 0
		for _, roomID := range rooms {
			if resp != nil && slices.Contains(resp.JoinedRooms, roomID) {
				log.Debug().
					Stringer("user_id", userID).
					Stringer("room_id", roomID).
					Msg("Room is already joined, not rejecting invite")
			} else if pe.DryRun {
				log.Debug().
					Stringer("user_id", userID).
					Stringer("room_id", roomID).
					Msg("Dry run, not actually rejecting invite")
				successfullyRejected++
			} else if _, err = client.LeaveRoom(ctx, roomID); err != nil {
				log.Err(err).
					Stringer("user_id", userID).
					Stringer("room_id", roomID).
					Msg("Failed to reject invite")
			} else {
				log.Debug().
					Stringer("user_id", userID).
					Stringer("room_id", roomID).
					Msg("Rejected invite")
				successfullyRejected++
			}
		}
		pe.sendNotice(
			ctx,
			"Rejected %d/%d invites to [%s](%s) from [%s](%s) due to policy banning `%s` for `%s`",
			successfullyRejected, len(rooms),
			userID, userID.URI().MatrixToURL(),
			inviter, inviter.URI().MatrixToURL(),
			rec.EntityOrHash(), rec.Reason,
		)
	}
}
