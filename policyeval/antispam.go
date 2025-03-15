package policyeval

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policylist"
)

func (pe *PolicyEvaluator) HandleUserMayInvite(ctx context.Context, inviter, invitee id.UserID, roomID id.RoomID) *mautrix.RespError {
	log := zerolog.Ctx(ctx).With().
		Stringer("inviter", inviter).
		Stringer("invitee", invitee).
		Stringer("room_id", roomID).
		Logger()
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
		return ptr.Ptr(mautrix.MForbidden.WithMessage(fmt.Sprintf("You're not allowed to send invites due to %s", rec.Reason)))
	}

	if rec = pe.Store.MatchRoom(lists, roomID).Recommendations().BanOrUnban; rec != nil && rec.Recommendation != event.PolicyRecommendationUnban {
		log.Debug().
			Str("policy_entity", rec.EntityOrHash()).
			Str("policy_reason", rec.Reason).
			Msg("Blocking invite to banned room")
		return ptr.Ptr(mautrix.MForbidden.WithMessage(fmt.Sprintf("Inviting to this room is not allowed due to %s", rec.Reason)))
	}

	inviterServer := inviter.Homeserver()
	if rec = pe.Store.MatchServer(lists, inviterServer).Recommendations().BanOrUnban; rec != nil && rec.Recommendation != event.PolicyRecommendationUnban {
		log.Debug().
			Str("policy_entity", rec.EntityOrHash()).
			Str("policy_reason", rec.Reason).
			Msg("Blocking invite from banned server")
		return ptr.Ptr(mautrix.MForbidden.WithMessage(fmt.Sprintf("Inviting from your server (%s) is not allowed due to %s", inviterServer, rec.Reason)))
	}

	log.Trace().Msg("Allowing invite")
	return nil
}
