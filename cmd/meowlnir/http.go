package main

import (
	"net/http"
	"slices"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/requestlog"
)

func (m *Meowlnir) AddHTTPEndpoints() {
	clientRouter := http.NewServeMux()
	clientRouter.HandleFunc("POST /v3/rooms/{roomID}/report/{eventID}", m.PostReport)
	clientRouter.HandleFunc("POST /v3/rooms/{roomID}", m.PostReport)
	clientRouter.HandleFunc("POST /v3/users/{userID}/report", m.PostReport)
	m.AS.Router.PathPrefix("/_matrix/client").Handler(applyMiddleware(
		http.StripPrefix("/_matrix/client", clientRouter),
		hlog.NewHandler(m.Log.With().Str("component", "reporting api").Logger()),
		exhttp.CORSMiddleware,
		requestlog.AccessLogger(false),
		m.ClientAuth,
	))

	managementRouter := http.NewServeMux()
	managementRouter.HandleFunc("GET /v1/bots", m.GetBots)
	managementRouter.HandleFunc("PUT /v1/bot/{username}", m.PutBot)
	managementRouter.HandleFunc("POST /v1/bot/{username}/verify", m.PostVerifyBot)
	managementRouter.HandleFunc("PUT /v1/management_room/{roomID}", m.PutManagementRoom)
	m.AS.Router.PathPrefix("/_meowlnir").Handler(applyMiddleware(
		http.StripPrefix("/_meowlnir", managementRouter),
		hlog.NewHandler(m.Log.With().Str("component", "management api").Logger()),
		exhttp.CORSMiddleware,
		requestlog.AccessLogger(false),
		m.ManagementAuth,
	))
}

func applyMiddleware(router http.Handler, middleware ...func(http.Handler) http.Handler) http.Handler {
	slices.Reverse(middleware)
	for _, m := range middleware {
		router = m(router)
	}
	return router
}
