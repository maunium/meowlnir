//go:build goexperiment.jsonv2

package main

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"regexp"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policyeval"
)

var eventIDRegex = regexp.MustCompile(`^\$[A-Za-z0-9_-]{43}$`)

const pduSizeLimit = 64 * 1024           // 64 KiB
const bodySizeLimit = pduSizeLimit * 1.5 // Leave a bit of room for whitespace

func (m *Meowlnir) PostMSC4284LegacyEventCheck(w http.ResponseWriter, r *http.Request) {
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
		resp, err := m.PolicyServer.HandleCachedLegacyCheck(r.Context(), eventID)
		if err != nil {
			hlog.FromRequest(r).Err(err).Msg("Failed to handle check")
			mautrix.MUnknown.WithMessage("Policy server error: internal server error").Write(w)
			return
		} else if resp.Recommendation == "spam" && m.Config.Meowlnir.DryRun {
			exhttp.WriteJSONResponse(w, http.StatusOK, &policyeval.LegacyPolicyServerResponse{Recommendation: "ok"})
		} else {
			exhttp.WriteJSONResponse(w, http.StatusOK, resp)
		}
		return
	}
	var parsedPDU *pdu.PDU
	err := json.UnmarshalRead(io.LimitReader(r.Body, bodySizeLimit), &parsedPDU)
	if err != nil {
		mautrix.MNotJSON.WithMessage("Request body is not valid JSON").Write(w)
		return
	}
	var ok bool
	m.MapLock.RLock()
	eval, ok := m.EvaluatorByProtectedRoom[parsedPDU.RoomID]
	m.MapLock.RUnlock()
	if !ok {
		mautrix.MNotFound.WithMessage("Policy server error: room is not protected").Write(w)
		return
	}
	createEvt := eval.GetProtectedRoomCreateEvent(parsedPDU.RoomID)
	if createEvt == nil {
		mautrix.MNotFound.WithMessage("Policy server error: room create event not found").Write(w)
		return
	}
	expectedEventID, err := parsedPDU.GetEventID(createEvt.RoomVersion)
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to calculate event ID from PDU")
		mautrix.MUnknown.WithMessage("Failed to calculate event ID from PDU").Write(w)
		return
	} else if expectedEventID != eventID {
		mautrix.MInvalidParam.WithMessage("Event ID does not match hash of request body").Write(w)
		return
	}

	resp, err := m.PolicyServer.HandleLegacyCheck(
		r.Context(),
		createEvt.RoomVersion,
		eventID,
		parsedPDU,
		eval,
	)
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to handle check")
		mautrix.MUnknown.WithMessage("Policy server error: internal server error").Write(w)
		return
	}
	if resp.Recommendation == "spam" && m.Config.Meowlnir.DryRun {
		hlog.FromRequest(r).Warn().Msg("Event would have been marked as spam, but dry run is enabled")
		resp = &policyeval.LegacyPolicyServerResponse{Recommendation: "ok"}
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, resp)
}

func (m *Meowlnir) PostMSC4284Sign(w http.ResponseWriter, r *http.Request) {
	if m.PolicyServer.SigningKey == nil {
		mautrix.MUnknown.WithMessage("Policy server signing key is not configured").Write(w)
		return
	}
	var parsedPDU *pdu.PDU
	err := json.UnmarshalRead(io.LimitReader(r.Body, bodySizeLimit), &parsedPDU)
	if err != nil {
		mautrix.MNotJSON.WithMessage("Request body is not valid JSON").Write(w)
		return
	}
	var ok bool
	m.MapLock.RLock()
	eval, ok := m.EvaluatorByProtectedRoom[parsedPDU.RoomID]
	m.MapLock.RUnlock()
	if !ok {
		mautrix.MNotFound.WithMessage("Policy server error: room is not protected").Write(w)
		return
	}
	createEvt := eval.GetProtectedRoomCreateEvent(parsedPDU.RoomID)
	if createEvt == nil {
		mautrix.MNotFound.WithMessage("Policy server error: room create event not found").Write(w)
		return
	}

	err = m.PolicyServer.HandleSign(r.Context(), createEvt.RoomVersion, parsedPDU, eval, federation.OriginServerNameFromRequest(r))
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to handle check")
		mautrix.MUnknown.WithMessage("Policy server error: internal server error").Write(w)
		return
	}
	_, ok = parsedPDU.Signatures[m.PolicyServer.Federation.ServerName][policyeval.PolicyServerKeyID]
	sigs := map[string]map[id.KeyID]string{}
	if ok {
		//sigs[m.PolicyServer.Federation.ServerName] = map[id.KeyID]string{policyeval.PolicyServerKeyID: sig}
		// Return all signatures to work around a synapse bug where it only does a shallow merge
		// https://github.com/element-hq/synapse/blob/v1.148.0/synapse/handlers/room_policy.py#L177
		sigs[m.PolicyServer.Federation.ServerName] = parsedPDU.Signatures[m.PolicyServer.Federation.ServerName]
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, parsedPDU.Signatures)
}
