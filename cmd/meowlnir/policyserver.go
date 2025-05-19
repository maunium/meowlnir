package main

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/hlog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/util"
)

func (m *Meowlnir) PostMSC4284EventCheck(w http.ResponseWriter, r *http.Request) {
	eventID := id.EventID(r.PathValue("event_id"))
	var req util.EventPDU
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to parse request body")
		mautrix.MNotJSON.WithMessage("Policy Server request error: invalid JSON").Write(w)
		return
	}

	m.MapLock.RLock()
	eval, ok := m.EvaluatorByProtectedRoom[req.RoomID]
	m.MapLock.RUnlock()
	if !ok {
		mautrix.MNotFound.WithMessage("Antispam configuration issue: policy list not found").Write(w)
		return
	}
	resp, err := m.PolicyServer.HandleCheck(r.Context(), eventID, &req, eval, m.Config.PolicyServer.AlwaysRedact)
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to handle check")
		mautrix.MUnknown.WithMessage("Policy Server error: internal server error").Write(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(resp)
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to encode response")
		mautrix.MNotJSON.WithMessage("Policy Server error: invalid JSON").Write(w)
		return
	}
}
