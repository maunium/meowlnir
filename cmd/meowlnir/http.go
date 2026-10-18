package main

import (
	"net/http"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/requestlog"
	"maunium.net/go/mautrix"
)

func addLogComponent(component string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hlog.FromRequest(r).UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Str("component", component)
			})
			next.ServeHTTP(w, r)
		})
	}
}

func (m *Meowlnir) AddHTTPEndpoints() {
	m.AS.Middleware = append(m.AS.Middleware,
		hlog.NewHandler(*m.Log),
		hlog.RequestIDHandler("request_id", "X-Request-ID"),
		requestlog.AccessLogger(requestlog.Options{
			TrustXForwardedFor: true,
			OKLevel:            new(zerolog.DebugLevel),
		}),
		exhttp.HandleErrors(exhttp.ErrorBodies{
			NotFound:         exerrors.Must(new(mautrix.MUnrecognized.WithMessage("Unrecognized endpoint")).MarshalJSON()),
			MethodNotAllowed: exerrors.Must(new(mautrix.MUnrecognized.WithMessage("Invalid method for endpoint")).MarshalJSON()),
		}),
	)

	clientRouter := http.NewServeMux()
	clientRouter.HandleFunc("POST /v3/rooms/{roomID}/report/{eventID}", m.PostReport)
	clientRouter.HandleFunc("POST /v3/rooms/{roomID}/report", m.PostReport)
	clientRouter.HandleFunc("POST /v3/users/{userID}/report", m.PostReport)
	m.AS.Router.Handle("/_matrix/client/", exhttp.ApplyMiddleware(
		http.StripPrefix("/_matrix/client", clientRouter),
		addLogComponent("reporting api"),
		exhttp.CORSMiddleware,
		m.ClientAuth,
	))

	policyServerRouter := http.NewServeMux()
	policyServerRouter.HandleFunc("POST /v1/sign", m.PostPolicyServerSign)
	m.AS.Router.Handle("/_matrix/policy/", exhttp.ApplyMiddleware(
		http.StripPrefix("/_matrix/policy", policyServerRouter),
		addLogComponent("policy server"),
		m.PolicyServer.ServerAuth.AuthenticateMiddleware,
	))

	antispamRouter := http.NewServeMux()
	antispamRouter.HandleFunc("POST /{policyListID}/{callback}", m.PostCallback)
	m.AS.Router.Handle("/_meowlnir/antispam/", exhttp.ApplyMiddleware(
		http.StripPrefix("/_meowlnir/antispam", antispamRouter),
		addLogComponent("antispam api"),
		SecretAuth(m.loadSecret(m.Config.Antispam.Secret)),
	))

	dataRouter := http.NewServeMux()
	dataRouter.HandleFunc("GET /v1/match/{entityType}/{entity}", m.MatchPolicy)
	dataRouter.HandleFunc("GET /v1/list/{entityType}", m.ListPolicies)
	m.AS.Router.Handle("/_meowlnir/data/", exhttp.ApplyMiddleware(
		http.StripPrefix("/_meowlnir/data", dataRouter),
		addLogComponent("data api"),
		exhttp.CORSMiddleware,
		SecretAuth(m.loadSecret(m.Config.Meowlnir.DataSecret)),
	))

	mxauthRouter := http.NewServeMux()
	mxauthRouter.HandleFunc("GET /v1/match/{entityType}/{entity}", m.MatchPolicy)
	mxauthRouter.HandleFunc("GET /v1/management_rooms", m.GetManagementRoomsForUser)
	m.AS.Router.Handle("/_meowlnir/mxauth/", exhttp.ApplyMiddleware(
		http.StripPrefix("/_meowlnir/mxauth", mxauthRouter),
		addLogComponent("mxauth api"),
		exhttp.CORSMiddleware,
		m.MatrixFederationOAuth,
	))

	managementRouter := http.NewServeMux()
	managementRouter.HandleFunc("GET /v1/bots", m.GetBots)
	managementRouter.HandleFunc("PUT /v1/bot/{username}", m.PutBot)
	managementRouter.HandleFunc("DELETE /v1/bot/{username}", m.DeleteBot)
	managementRouter.HandleFunc("POST /v1/bot/{username}/verify", m.PostVerifyBot)
	managementRouter.HandleFunc("PUT /v1/management_room/{roomID}", m.PutManagementRoom)
	managementRouter.HandleFunc("DELETE /v1/management_room/{roomID}", m.DeleteManagementRoom)
	m.AS.Router.Handle("/_meowlnir/", exhttp.ApplyMiddleware(
		http.StripPrefix("/_meowlnir", managementRouter),
		addLogComponent("management api"),
		exhttp.CORSMiddleware,
		SecretAuth(m.loadSecret(m.Config.Meowlnir.ManagementSecret)),
	))
}
