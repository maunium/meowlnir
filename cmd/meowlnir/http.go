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
		hlog.RequestIDHandler("request_id", "X-Request-ID"),
		exhttp.CORSMiddleware,
		requestlog.AccessLogger(false),
		m.ClientAuth,
	))

	policyServerRouter := http.NewServeMux()
	policyServerRouter.HandleFunc("POST /unstable/org.matrix.msc4284/event/{event_id}/check", m.PostMSC4284EventCheck)
	m.AS.Router.PathPrefix("/_matrix/policy").Handler(applyMiddleware(
		http.StripPrefix("/_matrix/policy", policyServerRouter),
		hlog.NewHandler(m.Log.With().Str("component", "policy server").Logger()),
		hlog.RequestIDHandler("request_id", "X-Request-ID"),
		requestlog.AccessLogger(false),
		m.PolicyServer.ServerAuth.AuthenticateMiddleware,
	))

	antispamRouter := http.NewServeMux()
	antispamRouter.HandleFunc("POST /{policyListID}/{callback}", m.PostCallback)
	m.AS.Router.PathPrefix("/_meowlnir/antispam").Handler(applyMiddleware(
		http.StripPrefix("/_meowlnir/antispam", antispamRouter),
		hlog.NewHandler(m.Log.With().Str("component", "antispam api").Logger()),
		hlog.RequestIDHandler("request_id", "X-Request-ID"),
		requestlog.AccessLogger(false),
		m.AntispamAuth,
	))

	managementRouter := http.NewServeMux()
	managementRouter.HandleFunc("GET /v1/bots", m.GetBots)
	managementRouter.HandleFunc("PUT /v1/bot/{username}", m.PutBot)
	managementRouter.HandleFunc("POST /v1/bot/{username}/verify", m.PostVerifyBot)
	managementRouter.HandleFunc("PUT /v1/management_room/{roomID}", m.PutManagementRoom)
	m.AS.Router.PathPrefix("/_meowlnir").Handler(applyMiddleware(
		http.StripPrefix("/_meowlnir", managementRouter),
		hlog.NewHandler(m.Log.With().Str("component", "management api").Logger()),
		hlog.RequestIDHandler("request_id", "X-Request-ID"),
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
