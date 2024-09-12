package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/rs/zerolog/hlog"
	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/ptr"
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

type PutBotRequest struct {
	Displayname *string        `json:"displayname"`
	AvatarURL   *id.ContentURI `json:"avatar_url"`
}

func (m *Meowlnir) PutBot(w http.ResponseWriter, r *http.Request) {
	var req PutBotRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		mautrix.MBadJSON.WithMessage("Invalid JSON").Write(w)
		return
	}
	username := r.PathValue("username")
	userID := id.NewUserID(username, m.AS.HomeserverDomain)
	m.MapLock.Lock()
	defer m.MapLock.Unlock()
	bot, ok := m.Bots[userID]
	if !ok {
		dbBot := &database.Bot{
			Username:    username,
			Displayname: ptr.Val(req.Displayname),
			AvatarURL:   ptr.Val(req.AvatarURL),
		}
		err = m.DB.Bot.Put(r.Context(), dbBot)
		if err != nil {
			hlog.FromRequest(r).Err(err).Msg("Failed to save bot to database")
			mautrix.MUnknown.WithMessage("Failed to save new bot to database").Write(w)
			return
		}
		bot = m.initBot(r.Context(), dbBot)
	} else {
		if req.Displayname != nil && bot.Meta.Displayname != *req.Displayname {
			err = bot.Intent.SetDisplayName(r.Context(), *req.Displayname)
			if err != nil {
				bot.Log.Err(err).Msg("Failed to set displayname")
			} else {
				bot.Meta.Displayname = *req.Displayname
			}
		}
		if req.AvatarURL != nil && bot.Meta.AvatarURL != *req.AvatarURL {
			err = bot.Intent.SetAvatarURL(r.Context(), *req.AvatarURL)
			if err != nil {
				bot.Log.Err(err).Msg("Failed to set avatar")
			} else {
				bot.Meta.AvatarURL = *req.AvatarURL
			}
		}
		err = m.DB.Bot.Put(r.Context(), bot.Meta)
		if err != nil {
			bot.Log.Err(err).Msg("Failed to save bot to database")
			mautrix.MUnknown.WithMessage("Failed to save updated bot to database").Write(w)
			return
		}
	}
	exhttp.WriteJSONResponse(w, http.StatusOK, bot.Meta)
}

func (m *Meowlnir) PostVerifyBot(w http.ResponseWriter, r *http.Request) {

}

func (m *Meowlnir) PutManagementRoom(w http.ResponseWriter, r *http.Request) {

}
