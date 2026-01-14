package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policyeval"
)

type ReqUserMayInvite struct {
	Inviter id.UserID `json:"inviter"`
	Invitee id.UserID `json:"invitee"`
	Room    id.RoomID `json:"room_id"`
}

type ReqFederatedUserMayInvite struct {
	Event *event.Event `json:"event"`
}

type ReqUserMayJoinRoom struct {
	UserID    id.UserID `json:"user"`
	RoomID    id.RoomID `json:"room"`
	IsInvited bool      `json:"is_invited"`
}

type ReqAcceptMakeJoin struct {
	RoomID id.RoomID `json:"room"`
	UserID id.UserID `json:"user"`
}

func (m *Meowlnir) PostCallback(w http.ResponseWriter, r *http.Request) {
	cbType := r.PathValue("callback")
	switch cbType {
	case "user_may_invite":
		m.PostUserMayInvite(w, r)
	case "federated_user_may_invite":
		m.PostFederatedUserMayInvite(w, r)
	case "accept_make_join":
		m.PostAcceptMakeJoin(w, r)
	case "user_may_join_room":
		m.PostUserMayJoinRoom(w, r)
	case "ping":
		m.PostAntispamPing(w, r)
	default:
		hlog.FromRequest(r).Warn().Str("callback", cbType).Msg("Unknown callback type")
		// Don't reject unknown callbacks, just ignore them
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	}
}

type ReqPing struct {
	Status string `json:"status"`
	ID     string `json:"id"`
}

func (m *Meowlnir) PostAntispamPing(w http.ResponseWriter, r *http.Request) {
	var req ReqPing
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to parse request body")
		mautrix.MNotJSON.WithMessage("Antispam request error: invalid JSON").Write(w)
		return
	}
	req.Status = "ok"
	exhttp.WriteJSONResponse(w, http.StatusOK, req)
	hlog.FromRequest(r).Info().Str("ping_id", req.ID).Msg("Received ping from antispam client")
}

func (m *Meowlnir) PostUserMayJoinRoom(w http.ResponseWriter, r *http.Request) {
	var req ReqUserMayJoinRoom
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
	exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	ctx := context.WithoutCancel(r.Context())
	go mgmtRoom.HandleUserMayJoinRoom(ctx, req.UserID, req.RoomID, req.IsInvited)
	go m.handlePotentialRoomBan(ctx, req.RoomID)
}

func (m *Meowlnir) handlePotentialRoomBan(ctx context.Context, roomID id.RoomID) {
	m.MapLock.RLock()
	mgmtRoom, ok := m.EvaluatorByManagementRoom[m.Config.Meowlnir.RoomBanRoom]
	m.MapLock.RUnlock()
	if !ok {
		return
	}
	if m.RoomHashes.Put(roomID) {
		mgmtRoom.EvaluateRoom(ctx, roomID, false)
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
	errResp := mgmtRoom.HandleUserMayInvite(r.Context(), req.Inviter, req.Invitee, req.Room, "")
	if errResp != nil {
		errResp.Write(w)
	} else {
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	}
}

func (m *Meowlnir) PostFederatedUserMayInvite(w http.ResponseWriter, r *http.Request) {
	var req ReqFederatedUserMayInvite
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
	errResp := mgmtRoom.HandleFederatedUserMayInvite(r.Context(), req.Event)
	if errResp != nil {
		errResp.Write(w)
	} else {
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	}
}

func (m *Meowlnir) PostAcceptMakeJoin(w http.ResponseWriter, r *http.Request) {
	var req ReqAcceptMakeJoin
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to parse request body")
		mautrix.MNotJSON.WithMessage("Antispam request error: invalid JSON").Write(w)
		return
	}

	pathID := r.PathValue("policyListID")
	var mgmtRoom *policyeval.PolicyEvaluator
	var ok bool
	m.MapLock.RLock()
	if pathID == "auto" {
		mgmtRoom, ok = m.EvaluatorByProtectedRoom[req.RoomID]
	} else {
		mgmtRoom, ok = m.EvaluatorByManagementRoom[id.RoomID(pathID)]
	}
	m.MapLock.RUnlock()
	if !ok {
		if pathID == "auto" {
			mautrix.MNotFound.WithMessage("Antispam configured to auto-route accept_make_join, but the room is not protected").Write(w)
		} else {
			mautrix.MNotFound.WithMessage("Antispam configuration issue: policy list not found").Write(w)
		}
		return
	}
	errResp := mgmtRoom.HandleAcceptMakeJoin(r.Context(), req.RoomID, req.UserID)
	if errResp != nil {
		errResp.Write(w)
	} else {
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	}
}
