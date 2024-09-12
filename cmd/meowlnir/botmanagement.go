package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/database"
)

type RespManagementRoom struct {
	RoomID         id.RoomID   `json:"room_id"`
	ProtectedRooms []id.RoomID `json:"protected_rooms"`
	WatchedLists   []id.RoomID `json:"watched_lists"`
	Admins         []id.UserID `json:"admins"`
}

type RespBot struct {
	*database.Bot
	UserID            id.UserID             `json:"user_id"`
	DeviceID          id.DeviceID           `json:"device_id"`
	Verified          bool                  `json:"verified"`
	CrossSigningSetUp bool                  `json:"cross_signing_set_up"`
	ManagementRooms   []*RespManagementRoom `json:"management_rooms"`
}

type RespGetBots struct {
	Bots []*RespBot `json:"bots"`
}

func (m *Meowlnir) ManagementAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHash := sha256.Sum256([]byte(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")))
		if !hmac.Equal(authHash[:], m.ManagementSecret[:]) {
			mautrix.MUnknownToken.WithMessage("Invalid management secret").Write(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Meowlnir) GetBots(w http.ResponseWriter, r *http.Request) {
	m.MapLock.RLock()
	bots := slices.Collect(maps.Values(m.Bots))
	mgmtRooms := slices.Collect(maps.Values(m.EvaluatorByManagementRoom))
	m.MapLock.RUnlock()
	resp := &RespGetBots{Bots: make([]*RespBot, len(bots))}
	for i, bot := range bots {
		verified, csSetUp, err := bot.GetVerificationStatus(r.Context())
		if err != nil {
			hlog.FromRequest(r).Err(err).Str("bot_username", bot.Meta.Username).Msg("Failed to get bot verification status")
			mautrix.MUnknown.WithMessage("Failed to get bot verification status").Write(w)
			return
		}
		botMgmtRooms := make([]*RespManagementRoom, 0)
		for _, room := range mgmtRooms {
			if room.Bot != bot {
				continue
			}
			botMgmtRooms = append(botMgmtRooms, &RespManagementRoom{
				RoomID:         room.ManagementRoom,
				ProtectedRooms: room.GetProtectedRooms(),
				WatchedLists:   room.GetWatchedLists(),
				Admins:         room.Admins.AsList(),
			})
		}
		resp.Bots[i] = &RespBot{
			Bot:               bot.Meta,
			UserID:            bot.Client.UserID,
			DeviceID:          bot.Client.DeviceID,
			Verified:          verified,
			CrossSigningSetUp: csSetUp,
			ManagementRooms:   botMgmtRooms,
		}
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, resp)
}

func (m *Meowlnir) PutBot(w http.ResponseWriter, r *http.Request) {

}

func (m *Meowlnir) PostVerifyBot(w http.ResponseWriter, r *http.Request) {

}

func (m *Meowlnir) PutManagementRoom(w http.ResponseWriter, r *http.Request) {

}
