package main

import (
	"context"
	"net/http"
	"sync"
	"time"

	"go.mau.fi/util/exhttp"
)

type RespHealth struct {
	Ok        bool `json:"ok"`
	PrimaryDB bool `json:"primary_db"`
	SynapseDB bool `json:"synapse_db"`
}

// GetHealth - GET /_meowlnir/v1/health
func (m *Meowlnir) GetHealth(w http.ResponseWriter, r *http.Request) {
	var resp RespHealth
	var wg sync.WaitGroup
	pingDeadline, abort := context.WithTimeout(r.Context(), time.Second*5)
	defer abort()
	wg.Go(func() {
		resp.PrimaryDB = m.DB.RawDB.PingContext(pingDeadline) == nil
	})
	if m.SynapseDB != nil {
		wg.Go(func() {
			resp.SynapseDB = m.SynapseDB.DB.RawDB.PingContext(pingDeadline) == nil
		})
	} else {
		// Always report SynapseDB as healthy if it's not actually configured.
		// Can't have an unhealthy connection to nothing.
		resp.SynapseDB = true
	}
	wg.Wait()
	resp.Ok = resp.PrimaryDB && resp.SynapseDB
	if resp.Ok {
		exhttp.WriteJSONResponse(w, http.StatusOK, resp)
	} else {
		exhttp.WriteJSONResponse(w, http.StatusServiceUnavailable, resp)
	}
}
