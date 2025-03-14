package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policylist"
)

type ReqUserMayInvite struct {
	Inviter id.UserID `json:"inviter"`
	Invitee id.UserID `json:"invitee"`
	Room    id.RoomID `json:"room_id"`
}

func (m *Meowlnir) PostCallback(w http.ResponseWriter, r *http.Request) {
	cbType := r.PathValue("callback")
	switch cbType {
	case "user_may_invite":
		m.PostUserMayInvite(w, r)
	default:
		hlog.FromRequest(r).Warn().Str("callback", cbType).Msg("Unknown callback type")
		// Don't reject unknown callbacks, just ignore them
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	}
}

func (m *Meowlnir) PostUserMayInvite(w http.ResponseWriter, r *http.Request) {
	var req ReqUserMayInvite
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to parse request body")
		mautrix.MNotJSON.WithMessage("Antispam request error: invalid JSON").Write(w)
		return
	}

	m.MapLock.RLock()
	mgmtRoom, ok := m.EvaluatorByManagementRoom[id.RoomID(r.PathValue("policyListID"))]
	m.MapLock.RUnlock()
	if !ok {
		mautrix.MNotFound.WithMessage("Antispam configuration issue: policy list not found").Write(w)
		return
	}
	log := hlog.FromRequest(r).With().
		Stringer("inviter", req.Inviter).
		Stringer("invitee", req.Invitee).
		Stringer("room", req.Room).
		Logger()

	lists := mgmtRoom.GetWatchedLists()
	var rec *policylist.Policy
	defer func() {
		if rec != nil {
			go mgmtRoom.Bot.SendNotice(
				context.WithoutCancel(r.Context()), mgmtRoom.ManagementRoom,
				"Blocked [%s](%s) from inviting [%s](%s) to [%s](%s) due to policy banning `%s` for `%s`",
				req.Inviter, req.Inviter.URI().MatrixToURL(),
				req.Invitee, req.Invitee.URI().MatrixToURL(),
				req.Room, req.Room.URI().MatrixToURL(),
				rec.EntityOrHash(), rec.Reason,
			)
		}
	}()
	if rec = mgmtRoom.Store.MatchUser(lists, req.Inviter).Recommendations().BanOrUnban; rec != nil && rec.Recommendation != event.PolicyRecommendationUnban {
		log.Debug().
			Str("policy_entity", rec.EntityOrHash()).
			Str("policy_reason", rec.Reason).
			Msg("Blocking invite from banned user")
		mautrix.MForbidden.
			WithMessage(fmt.Sprintf("You're not allowed to send invites due to %s", rec.Reason)).
			Write(w)
		return
	}

	if rec = mgmtRoom.Store.MatchRoom(lists, req.Room).Recommendations().BanOrUnban; rec != nil && rec.Recommendation != event.PolicyRecommendationUnban {
		log.Debug().
			Str("policy_entity", rec.EntityOrHash()).
			Str("policy_reason", rec.Reason).
			Msg("Blocking invite to banned room")
		mautrix.MForbidden.
			WithMessage(fmt.Sprintf("Inviting to this room is not allowed due to %s", rec.Reason)).
			Write(w)
		return
	}

	inviterServer := req.Inviter.Homeserver()
	if rec = mgmtRoom.Store.MatchServer(lists, inviterServer).Recommendations().BanOrUnban; rec != nil && rec.Recommendation != event.PolicyRecommendationUnban {
		log.Debug().
			Str("policy_entity", rec.EntityOrHash()).
			Str("policy_reason", rec.Reason).
			Msg("Blocking invite from banned server")
		mautrix.MForbidden.
			WithMessage(fmt.Sprintf("Inviting from your server (%s) is not allowed due to %s", inviterServer, rec.Reason)).
			Write(w)
		return
	}

	log.Trace().Msg("Allowing invite")
	exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	rec = nil
}
