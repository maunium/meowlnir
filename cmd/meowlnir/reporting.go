package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"
)

type contextKey int

const contextKeyClientUserID contextKey = iota

func (m *Meowlnir) ClientAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if authToken == "" {
			mautrix.MMissingToken.WithMessage("Missing access token").Write(w)
			return
		}
		resp, err := m.checkMatrixAuth(r.Context(), authToken)
		if err != nil {
			if errors.Is(err, mautrix.MUnknownToken) {
				mautrix.MUnknownToken.WithMessage("Unknown access token").Write(w)
			} else {
				mautrix.MUnknown.WithMessage("Failed to validate access token").Write(w)
			}
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKeyClientUserID, resp.UserID)))
	})
}

func (m *Meowlnir) checkMatrixAuth(ctx context.Context, token string) (*mautrix.RespWhoami, error) {
	client, err := m.AS.NewExternalMautrixClient("", token, "")
	if err != nil {
		return nil, err
	}
	return client.Whoami(ctx)
}

func (m *Meowlnir) PostReport(w http.ResponseWriter, r *http.Request) {
	var req mautrix.ReqReport
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		mautrix.MBadJSON.WithMessage("Invalid JSON").Write(w)
		return
	}
	m.MapLock.RLock()
	mgmtRoom, ok := m.EvaluatorByManagementRoom[m.Config.Meowlnir.ReportRoom]
	m.MapLock.RUnlock()
	if !ok {
		mautrix.MUnrecognized.WithMessage("Reporting is not configured correctly").Write(w)
		return
	}

	roomID := id.RoomID(r.PathValue("roomID"))
	eventID := id.EventID(r.PathValue("eventID"))
	userID := r.Context().Value(contextKeyClientUserID).(id.UserID)
	log := hlog.FromRequest(r).With().
		Stringer("report_room_id", roomID).
		Stringer("report_event_id", eventID).
		Stringer("reporter_sender", userID).
		Str("action", "handle report").
		Logger()
	ctx := context.WithoutCancel(log.WithContext(r.Context()))
	err = mgmtRoom.HandleReport(ctx, userID, roomID, eventID, req.Reason)
	if err != nil {
		log.Err(err).Msg("Failed to handle report")
		var respErr mautrix.RespError
		if errors.As(err, &respErr) {
			respErr.Write(w)
		} else {
			mautrix.MUnknown.WithMessage(err.Error()).Write(w)
		}
	} else {
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	}
}
