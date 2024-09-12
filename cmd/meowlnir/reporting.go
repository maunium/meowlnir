package main

import (
	"encoding/json"
	"net/http"

	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix"
)

func (m *Meowlnir) PostReport(w http.ResponseWriter, r *http.Request) {
	var req mautrix.ReqReport
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		mautrix.MBadJSON.WithMessage("Invalid JSON").Write(w)
		return
	}
	//roomID := id.RoomID(mux.Vars(r)["roomID"])
	//eventID := id.EventID(mux.Vars(r)["eventID"])
	//m.MapLock.RLock()
	//protectedRoom, ok := m.EvaluatorByProtectedRoom[roomID]
	//m.MapLock.RUnlock()
	exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
}
