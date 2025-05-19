package main

import (
	"encoding/json"
	"net/http"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/util"
)

func (m *Meowlnir) FederationAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if m.Config.PolicyServer.SigningKey != nil && *m.Config.PolicyServer.SigningKey != "" {
			ourKey, err := federation.ParseSynapseKey(*m.Config.PolicyServer.SigningKey)
			if err != nil {
				hlog.FromRequest(r).Err(err).Msg("Failed to parse our own signing key")
				mautrix.MUnknown.WithMessage("Policy Server error: invalid signing key").Write(w)
				return
			}
			auth := federation.ParseXMatrixAuth(r.Header.Get("X-Matrix"))
			var body []byte
			if r.Body != nil {
				_, err = r.Body.Read(body)
				if err != nil {
					hlog.FromRequest(r).Err(err).Msg("Failed to read request body")
					mautrix.MUnknown.WithMessage("Policy Server error: invalid request body").Write(w)
					return
				}
			}
			client := federation.NewClient("meowlnir", ourKey, federation.NewInMemoryCache())
			ask := &federation.ReqQueryKeys{
				ServerKeys: map[string]map[id.KeyID]federation.QueryKeysCriteria{
					auth.Origin: {
						auth.KeyID: {
							MinimumValidUntilTS: jsontime.UnixMilliNow(),
						},
					},
				},
			}
			keys, err := client.QueryKeys(r.Context(), auth.Origin, ask)
			if err != nil {
				hlog.FromRequest(r).Err(err).Msg("Failed to query keys")
				mautrix.MForbidden.WithMessage("Policy Server error: unknown signing key").Write(w)
				return
			}
			key, ok := keys.VerifyKeys[auth.KeyID]
			if !ok {
				hlog.FromRequest(r).Err(err).Msg("Failed to verify key")
				mautrix.MForbidden.WithMessage("Policy Server error: invalid/expired signing key").Write(w)
				return
			}
			if !federation.VerifyJSONRaw(key.Key, auth.Signature, body) {
				hlog.FromRequest(r).Err(err).Msg("Failed to verify signature")
				mautrix.MForbidden.WithMessage("Policy Server error: invalid signature").Write(w)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

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
	resp, err := m.PolicyServer.HandleCheck(r.Context(), eventID, &req, eval)
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
