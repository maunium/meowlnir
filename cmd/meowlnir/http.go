package main

import (
	"net/http"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/requestlog"
)

func (m *Meowlnir) AddHTTPEndpoints() {
	clientRouter := m.AS.Router.PathPrefix("/_matrix/client").Subrouter()
	clientRouter.Use(hlog.NewHandler(m.Log.With().Str("component", "reporting api").Logger()))
	clientRouter.Use(exhttp.CORSMiddleware)
	clientRouter.Use(requestlog.AccessLogger(false))
	clientRouter.HandleFunc("/v3/rooms/{roomID}/report/{eventID}", m.PostReport).Methods(http.MethodPost, http.MethodOptions)
	clientRouter.HandleFunc("/v3/rooms/{roomID}", m.PostReport).Methods(http.MethodPost, http.MethodOptions)

	managementRouter := m.AS.Router.PathPrefix("/_matrix/meowlnir").Subrouter()
	managementRouter.Use(hlog.NewHandler(m.Log.With().Str("component", "management api").Logger()))
	managementRouter.Use(exhttp.CORSMiddleware)
	managementRouter.Use(requestlog.AccessLogger(false))
	managementRouter.HandleFunc("/v1/...", m.PostReport).Methods(http.MethodPost, http.MethodOptions)
}

func (m *Meowlnir) PostReport(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("{}"))
}
