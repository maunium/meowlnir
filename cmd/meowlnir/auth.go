package main

import (
	"context"
	"crypto/hmac"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/util"
)

type contextKey int

const (
	contextKeyUserClient contextKey = iota
	contextKeyUserID
)

func disabledAPI(w http.ResponseWriter, r *http.Request) {
	mautrix.MUnknownToken.WithMessage("This API is disabled").Write(w)
}

func SecretAuth(secret *[32]byte) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if secret == nil {
			return http.HandlerFunc(disabledAPI)
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHash := util.SHA256String(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			if !hmac.Equal(authHash[:], secret[:]) {
				mautrix.MUnknownToken.WithMessage("Invalid authorization token").Write(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (m *Meowlnir) ClientAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if authToken == "" {
			mautrix.MMissingToken.WithMessage("Missing access token").Write(w)
			return
		}
		client := exerrors.Must(m.AS.NewExternalMautrixClient("", authToken, ""))
		resp, err := client.Whoami(r.Context())
		if err != nil {
			if errors.Is(err, mautrix.MUnknownToken) {
				mautrix.MUnknownToken.WithMessage("Unknown access token").Write(w)
			} else {
				mautrix.MUnknown.WithMessage("Failed to validate access token").Write(w)
			}
			return
		}
		client.UserID = resp.UserID
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKeyUserClient, client)))
	})
}

type federationTokenCacheValue struct {
	exp    time.Time
	userID id.UserID
}

func (m *Meowlnir) checkMatrixOAuth(r *http.Request) (id.UserID, *mautrix.RespError) {
	fullToken := r.Header.Get("Authorization")
	cached, ok := m.federationTokenCache.Get(fullToken)
	if ok && time.Until(cached.exp) > 0 {
		return cached.userID, nil
	}
	parts := strings.SplitN(fullToken, ";", 2)
	if len(parts) != 2 {
		return "", ptr.Ptr(mautrix.MUnknownToken.WithMessage("Invalid Authorization header format"))
	}
	serverName := parts[0]
	token := parts[1]
	resp, err := m.Federation.GetOpenIDUserInfo(r.Context(), serverName, token)
	if err != nil {
		var respErr mautrix.RespError
		if errors.As(err, &respErr) && respErr.ErrCode == mautrix.MUnknownToken.ErrCode {
			return "", &respErr
		}
		hlog.FromRequest(r).Err(err).Msg("Failed to verify access token")
		return "", ptr.Ptr(mautrix.MUnknownToken.WithMessage("Failed to verify access token"))
	}
	_, realServerName, err := resp.Sub.ParseAndValidateRelaxed()
	if err != nil {
		return "", ptr.Ptr(mautrix.MUnknownToken.WithMessage("Invalid user ID in token verification response: %w", err))
	} else if realServerName != serverName {
		return "", ptr.Ptr(mautrix.MUnknownToken.WithMessage("Provided server name does not match returned server name (%q != %q)", serverName, realServerName))
	}
	m.federationTokenCache.Push(fullToken, federationTokenCacheValue{
		exp:    time.Now().Add(5 * time.Minute),
		userID: resp.Sub,
	})
	return resp.Sub, nil
}

func (m *Meowlnir) MatrixFederationOAuth(next http.Handler) http.Handler {
	if !m.Config.Meowlnir.FederationAuth {
		return http.HandlerFunc(disabledAPI)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := m.checkMatrixOAuth(r)
		if err != nil {
			err.Write(w)
			return
		}
		ctx := context.WithValue(r.Context(), contextKeyUserID, userID)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}
