package main

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policyeval"
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
	resp, err := m.PolicyServer.HandleCheck(
		r.Context(),
		eventID,
		&req,
		eval,
		m.Config.PolicyServer.AlwaysRedact && !m.Config.Meowlnir.DryRun,
		federation.OriginServerNameFromRequest(r))
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to handle check")
		mautrix.MUnknown.WithMessage("Policy server error: internal server error").Write(w)
		return
	}
	if resp.Recommendation == "spam" && m.Config.Meowlnir.DryRun {
		hlog.FromRequest(r).Warn().Msg("Event would have been marked as spam, but dry run is enabled")
		resp = &policyeval.PolicyServerResponse{Recommendation: "ok"}
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, resp)
}
