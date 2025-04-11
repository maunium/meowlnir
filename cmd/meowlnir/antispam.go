package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

type ReqUserMayInvite struct {
	Inviter id.UserID `json:"inviter"`
	Invitee id.UserID `json:"invitee"`
	Room    id.RoomID `json:"room_id"`
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
	case "accept_make_join":
		m.PostAcceptMakeJoin(w, r)
	case "user_may_join_room":
		m.PostUserMayJoinRoom(w, r)
	default:
		hlog.FromRequest(r).Warn().Str("callback", cbType).Msg("Unknown callback type")
		// Don't reject unknown callbacks, just ignore them
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	}
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
	go mgmtRoom.HandleUserMayJoinRoom(context.WithoutCancel(r.Context()), req.UserID, req.RoomID, req.IsInvited)
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
	errResp := mgmtRoom.HandleUserMayInvite(r.Context(), req.Inviter, req.Invitee, req.Room)
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

	m.MapLock.RLock()
	mgmtRoom, ok := m.EvaluatorByManagementRoom[id.RoomID(r.PathValue("policyListID"))]
	m.MapLock.RUnlock()
	if !ok {
		mautrix.MNotFound.WithMessage("Antispam configuration issue: policy list not found").Write(w)
		return
	}
	errResp := mgmtRoom.HandleAcceptMakeJoin(r.Context(), req.RoomID, req.UserID)
	if errResp != nil {
		errResp.Write(w)
	} else {
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	}
}
