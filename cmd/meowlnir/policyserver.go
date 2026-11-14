//go:build goexperiment.jsonv2 || go1.27

package main

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policyeval"
)

const pduSizeLimit = 64 * 1024           // 64 KiB
const bodySizeLimit = pduSizeLimit * 1.5 // Leave a bit of room for whitespace

func (m *Meowlnir) PostPolicyServerSign(w http.ResponseWriter, r *http.Request) {
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

	errorMessage, err := m.PolicyServer.HandleSign(r.Context(), createEvt.RoomVersion, parsedPDU, eval, federation.OriginServerNameFromRequest(r))
	if err != nil {
		if errors.Is(err, context.Canceled) && r.Context().Err() != nil {
			w.WriteHeader(499)
			return
		}
		hlog.FromRequest(r).Err(err).Msg("Failed to handle check")
		mautrix.MUnknown.WithMessage("Policy server error: internal server error").Write(w)
		return
	}
	sig, ok := parsedPDU.Signatures[m.PolicyServer.Federation.ServerName][policyeval.PolicyServerKeyID]
	sigs := map[string]map[id.KeyID]string{}
	if ok {
		sigs[m.PolicyServer.Federation.ServerName] = map[id.KeyID]string{policyeval.PolicyServerKeyID: sig}
	} else {
		mautrix.MForbidden.
			WithMessage(cmp.Or(errorMessage, "This message has been rejected as probable spam")).
			WithStatus(http.StatusBadRequest).
			Write(w)
		return
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, sigs)
}
