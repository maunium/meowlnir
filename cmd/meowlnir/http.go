package main

import (
	"net/http"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/requestlog"
)

func (m *Meowlnir) AddHTTPEndpoints() {
	clientRouter := http.NewServeMux()
	clientRouter.HandleFunc("POST /v3/rooms/{roomID}/report/{eventID}", m.PostReport)
	clientRouter.HandleFunc("POST /v3/rooms/{roomID}/report", m.PostReport)
	clientRouter.HandleFunc("POST /v3/users/{userID}/report", m.PostReport)
	m.AS.Router.Handle("/_matrix/client/", exhttp.ApplyMiddleware(
		http.StripPrefix("/_matrix/client", clientRouter),
		hlog.NewHandler(m.Log.With().Str("component", "reporting api").Logger()),
		hlog.RequestIDHandler("request_id", "X-Request-ID"),
		exhttp.CORSMiddleware,
		requestlog.AccessLogger(requestlog.Options{TrustXForwardedFor: true}),
		m.ClientAuth,
	))

	policyServerRouter := http.NewServeMux()
	policyServerRouter.HandleFunc("POST /unstable/org.matrix.msc4284/event/{event_id}/check", m.PostMSC4284LegacyEventCheck)
	m.AS.Router.Handle("/_matrix/policy/", exhttp.ApplyMiddleware(
		http.StripPrefix("/_matrix/policy", policyServerRouter),
		hlog.NewHandler(m.Log.With().Str("component", "policy server").Logger()),
		hlog.RequestIDHandler("request_id", "X-Request-ID"),
		requestlog.AccessLogger(requestlog.Options{TrustXForwardedFor: true}),
		m.PolicyServer.ServerAuth.AuthenticateMiddleware,
	))
	policyServerRouter.HandleFunc("POST /unstable/org.matrix.msc4284/sign", m.PostMSC4284Sign)
	m.AS.Router.Handle("/_matrix/policy/", exhttp.ApplyMiddleware(
		http.StripPrefix("/_matrix/policy", policyServerRouter),
		hlog.NewHandler(m.Log.With().Str("component", "policy server").Logger()),
		hlog.RequestIDHandler("request_id", "X-Request-ID"),
		requestlog.AccessLogger(requestlog.Options{TrustXForwardedFor: true}),
		m.PolicyServer.ServerAuth.AuthenticateMiddleware,
	))

	antispamRouter := http.NewServeMux()
	antispamRouter.HandleFunc("POST /{policyListID}/{callback}", m.PostCallback)
	m.AS.Router.Handle("/_meowlnir/antispam/", exhttp.ApplyMiddleware(
		http.StripPrefix("/_meowlnir/antispam", antispamRouter),
		hlog.NewHandler(m.Log.With().Str("component", "antispam api").Logger()),
		hlog.RequestIDHandler("request_id", "X-Request-ID"),
		requestlog.AccessLogger(requestlog.Options{TrustXForwardedFor: true}),
		SecretAuth(m.loadSecret(m.Config.Antispam.Secret)),
	))

	dataRouter := http.NewServeMux()
	dataRouter.HandleFunc("GET /v1/match/{entityType}/{entity}", m.MatchPolicy)
	dataRouter.HandleFunc("GET /v1/list/{entityType}", m.ListPolicies)
	m.AS.Router.Handle("/_meowlnir/data/", exhttp.ApplyMiddleware(
		http.StripPrefix("/_meowlnir/data", dataRouter),
		hlog.NewHandler(m.Log.With().Str("component", "data api").Logger()),
		hlog.RequestIDHandler("request_id", "X-Request-ID"),
		exhttp.CORSMiddleware,
		requestlog.AccessLogger(requestlog.Options{TrustXForwardedFor: true}),
		SecretAuth(m.loadSecret(m.Config.Meowlnir.DataSecret)),
	))

	managementRouter := http.NewServeMux()
	managementRouter.HandleFunc("GET /v1/bots", m.GetBots)
	managementRouter.HandleFunc("PUT /v1/bot/{username}", m.PutBot)
	managementRouter.HandleFunc("POST /v1/bot/{username}/verify", m.PostVerifyBot)
	managementRouter.HandleFunc("PUT /v1/management_room/{roomID}", m.PutManagementRoom)
	m.AS.Router.Handle("/_meowlnir/", exhttp.ApplyMiddleware(
		http.StripPrefix("/_meowlnir", managementRouter),
		hlog.NewHandler(m.Log.With().Str("component", "management api").Logger()),
		hlog.RequestIDHandler("request_id", "X-Request-ID"),
		exhttp.CORSMiddleware,
		requestlog.AccessLogger(requestlog.Options{TrustXForwardedFor: true}),
		SecretAuth(m.loadSecret(m.Config.Meowlnir.ManagementSecret)),
	))
}
