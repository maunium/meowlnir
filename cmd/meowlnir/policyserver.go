package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"regexp"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policyeval"
)

var eventIDRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

const pduSizeLimit = 64 * 1024           // 64 KiB
const bodySizeLimit = pduSizeLimit * 1.5 // Leave a bit of room for whitespace

func (m *Meowlnir) PostMSC4284EventCheck(w http.ResponseWriter, r *http.Request) {
	eventID := id.EventID(r.PathValue("event_id"))
	// Only room v4+ is supported
	if !eventIDRegex.MatchString(string(eventID)) {
		mautrix.MInvalidParam.WithMessage("Invalid event ID format").Write(w)
		return
	} else if r.ContentLength > bodySizeLimit {
		mautrix.MTooLarge.WithMessage("PDUs must be less than 64 KiB").Write(w)
		return
	}
	if r.ContentLength >= 0 && r.ContentLength <= 2 {
		resp := m.PolicyServer.HandleCachedCheck(eventID)
		if resp.Recommendation == "spam" && m.Config.Meowlnir.DryRun {
			exhttp.WriteJSONResponse(w, http.StatusOK, &policyeval.PolicyServerResponse{Recommendation: "ok"})
		} else {
			exhttp.WriteJSONResponse(w, http.StatusOK, resp)
		}
		return
	}
	var requestJSON []byte
	requestJSON, err := io.ReadAll(io.LimitReader(r.Body, bodySizeLimit))
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to read request body")
		w.WriteHeader(http.StatusBadRequest)
		return
	} else if !json.Valid(requestJSON) {
		mautrix.MNotJSON.WithMessage("Request body is not valid JSON").Write(w)
		return
	}
	requestJSON = canonicaljson.CanonicalJSONAssumeValid(requestJSON)
	referenceHash := sha256.Sum256(requestJSON)
	expectedEventID := id.EventID(base64.RawURLEncoding.EncodeToString(referenceHash[:]))
	if expectedEventID != eventID {
		mautrix.MInvalidParam.WithMessage("Event ID does not match hash of request body").Write(w)
		return
	}
	var req *event.Event
	err = json.Unmarshal(requestJSON, &req)
	if err != nil {
		mautrix.MBadJSON.WithMessage("Failed to parse event in request body").Write(w)
		return
	}
	var ok bool
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
		req,
		eval,
		m.Config.PolicyServer.AlwaysRedact && !m.Config.Meowlnir.DryRun,
		federation.OriginServerNameFromRequest(r),
	)
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
