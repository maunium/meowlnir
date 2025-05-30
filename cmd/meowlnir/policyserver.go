package main

import (
	"encoding/json"
	"net/http"

	"maunium.net/go/mautrix/event"

	"github.com/rs/zerolog/hlog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/util/exhttp"
)

func (m *Meowlnir) PostMSC4284EventCheck(w http.ResponseWriter, r *http.Request) {
	eventID := id.EventID(r.PathValue("event_id"))
	var req event.Event
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to parse request body")
		mautrix.MNotJSON.WithMessage("Request body is not valid JSON").Write(w)
		return
	}

	m.MapLock.RLock()
	eval, ok := m.EvaluatorByProtectedRoom[req.RoomID]
	m.MapLock.RUnlock()
	if !ok {
		mautrix.MNotFound.WithMessage("Policy server error: room is not protected").Write(w)
		return
	}
	resp, err := m.PolicyServer.HandleCheck(r.Context(), eventID, &req, eval, m.Config.Antispam.PolicyServer.AlwaysRedact)
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to handle check")
		mautrix.MUnknown.WithMessage("Policy server error: internal server error").Write(w)
		return
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, resp)
}
