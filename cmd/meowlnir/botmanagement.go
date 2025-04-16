package main

import (
	"context"
	"crypto/hmac"
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
	"go.mau.fi/meowlnir/util"
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
		authHash := util.SHA256String(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if !hmac.Equal(authHash[:], m.ManagementSecret[:]) {
			mautrix.MUnknownToken.WithMessage("Invalid management secret").Write(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Meowlnir) AntispamAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHash := util.SHA256String(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if !hmac.Equal(authHash[:], m.AntispamSecret[:]) {
			mautrix.MUnknown.WithMessage("Invalid antispam secret").Write(w)
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
		var verified, csSetUp bool
		if m.Config.Encryption.Enable {
			var err error
			verified, csSetUp, err = bot.GetVerificationStatus(r.Context())
			if err != nil {
				hlog.FromRequest(r).Err(err).Str("bot_username", bot.Meta.Username).Msg("Failed to get bot verification status")
				mautrix.MUnknown.WithMessage("Failed to get bot verification status").Write(w)
				return
			}
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

type ReqPutBot struct {
	Displayname *string        `json:"displayname"`
	AvatarURL   *id.ContentURI `json:"avatar_url"`
}

func (m *Meowlnir) PutBot(w http.ResponseWriter, r *http.Request) {
	var req ReqPutBot
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		mautrix.MNotJSON.WithMessage("Invalid JSON").Write(w)
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

var (
	ErrAlreadyVerified = mautrix.RespError{
		ErrCode:    "FI.MAU.MEOWLNIR.ALREADY_VERIFIED",
		Err:        "The bot is already verified.",
		StatusCode: http.StatusConflict,
	}
	ErrAlreadyHaveKeys = mautrix.RespError{
		ErrCode:    "FI.MAU.MEOWLNIR.ALREADY_HAS_KEYS",
		Err:        "The bot already has cross-signing set up.",
		StatusCode: http.StatusConflict,
	}
)

type ReqVerifyBot struct {
	RecoveryKey   string `json:"recovery_key"`
	Generate      bool   `json:"generate"`
	ForceGenerate bool   `json:"force_generate"`
	ForceVerify   bool   `json:"force_verify"`
}

type RespVerifyBot struct {
	RecoveryKey string `json:"recovery_key"`
}

func (m *Meowlnir) PostVerifyBot(w http.ResponseWriter, r *http.Request) {
	if !m.Config.Encryption.Enable {
		mautrix.MForbidden.WithMessage("Encryption is not enabled on this Meowlnir instance").Write(w)
		return
	}
	var req ReqVerifyBot
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		mautrix.MNotJSON.WithMessage("Invalid JSON").Write(w)
		return
	} else if !req.Generate && req.RecoveryKey == "" {
		mautrix.MBadJSON.WithMessage("Recovery key or generate flag must be provided").Write(w)
		return
	}
	userID := id.NewUserID(r.PathValue("username"), m.AS.HomeserverDomain)
	m.MapLock.RLock()
	bot, ok := m.Bots[userID]
	m.MapLock.RUnlock()
	if !ok {
		mautrix.MNotFound.WithMessage("Bot not found").Write(w)
		return
	}
	hasKeys, isVerified, err := bot.GetVerificationStatus(r.Context())
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to get bot verification status")
		mautrix.MUnknown.WithMessage("Failed to get bot verification status").Write(w)
		return
	} else if isVerified && !req.ForceVerify {
		ErrAlreadyVerified.Write(w)
		return
	} else if hasKeys && req.Generate && !req.ForceGenerate {
		ErrAlreadyHaveKeys.Write(w)
		return
	}
	if req.Generate {
		recoveryKey, err := bot.GenerateRecoveryKey(r.Context())
		if err != nil {
			hlog.FromRequest(r).Err(err).Msg("Failed to generate recovery key")
			mautrix.MUnknown.WithMessage("Failed to generate recovery key: " + err.Error()).Write(w)
		} else {
			exhttp.WriteJSONResponse(w, http.StatusCreated, &RespVerifyBot{RecoveryKey: recoveryKey})
		}
	} else {
		err = bot.VerifyWithRecoveryKey(r.Context(), req.RecoveryKey)
		if err != nil {
			hlog.FromRequest(r).Err(err).Msg("Failed to verify bot with recovery key")
			mautrix.MUnknown.WithMessage("Failed to verify bot with recovery key: " + err.Error()).Write(w)
		} else {
			exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
		}
	}
}

type ReqPutManagementRoom struct {
	BotUsername string `json:"bot_username"`
}

func (m *Meowlnir) PutManagementRoom(w http.ResponseWriter, r *http.Request) {
	var req ReqPutManagementRoom
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		mautrix.MNotJSON.WithMessage("Invalid JSON").Write(w)
		return
	}
	userID := id.NewUserID(req.BotUsername, m.AS.HomeserverDomain)
	m.MapLock.RLock()
	bot, ok := m.Bots[userID]
	m.MapLock.RUnlock()
	if !ok {
		mautrix.MNotFound.WithMessage("Bot not found").Write(w)
		return
	}
	roomID := id.RoomID(r.PathValue("roomID"))
	_, err = bot.JoinRoomByID(r.Context(), roomID)
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to join room")
	}
	err = m.DB.ManagementRoom.Put(r.Context(), roomID, bot.Meta.Username)
	if err != nil {
		hlog.FromRequest(r).Err(err).Msg("Failed to save management room to database")
		mautrix.MUnknown.WithMessage("Failed to save management room to database").Write(w)
		return
	}
	didUpdate := m.loadManagementRoom(context.WithoutCancel(r.Context()), roomID, bot)
	if didUpdate {
		exhttp.WriteEmptyJSONResponse(w, http.StatusCreated)
	} else {
		exhttp.WriteEmptyJSONResponse(w, http.StatusOK)
	}
}
