package policyeval

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/glob"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policylist"
	"go.mau.fi/meowlnir/util"
)

func (pe *PolicyEvaluator) HandleCommand(ctx context.Context, evt *event.Event) {
	if !evt.Mautrix.WasEncrypted && pe.Bot.CryptoHelper != nil {
		zerolog.Ctx(ctx).Warn().
			Msg("Dropping unencrypted command event")
		return
	} else if evt.Mautrix.WasEncrypted && evt.Mautrix.TrustState < id.TrustStateCrossSignedTOFU {
		zerolog.Ctx(ctx).Warn().
			Stringer("trust_state", evt.Mautrix.TrustState).
			Msg("Dropping encrypted event with insufficient trust state")
		return
	}
	msg := evt.Content.AsMessage()
	fields := strings.Fields(msg.Body)
	if len(fields) == 0 || len(fields[0]) < 2 || fields[0][0] != '!' {
		return
	}
	cmd := strings.ToLower(fields[0])
	args := fields[1:]
	zerolog.Ctx(ctx).Info().Str("command", cmd).Msg("Handling command")
	switch cmd {
	case "!join":
		if len(args) == 0 {
			pe.sendNotice(ctx, "Usage: `!join <room ID>...`")
			return
		}
		for _, arg := range args {
			_, err := pe.Bot.JoinRoom(ctx, arg, nil)
			if err != nil {
				pe.sendNotice(ctx, "Failed to join room %q: %v", arg, err)
			} else {
				pe.sendNotice(ctx, "Joined room %q", arg)
			}
		}
		pe.sendSuccessReaction(ctx, evt.ID)
	case "!knock":
		if len(args) == 0 {
			pe.sendNotice(ctx, "Usage: `!knock <rooms...>`")
			return
		}
		for _, arg := range args {
			_, err := pe.Bot.KnockRoom(ctx, arg, nil)
			if err != nil {
				pe.sendNotice(ctx, "Failed to knock on room %q: %v", arg, err)
			} else {
				pe.sendNotice(ctx, "Requested to join room %q", arg)
			}
		}
		pe.sendSuccessReaction(ctx, evt.ID)
	case "!leave":
		if len(args) == 0 {
			pe.sendNotice(ctx, "Usage: `!leave <room ID>...`")
			return
		}
		for _, arg := range args {
			target := pe.resolveRoom(ctx, arg)
			if target == "" {
				continue
			}
			_, err := pe.Bot.LeaveRoom(ctx, target)
			if err != nil {
				pe.sendNotice(ctx, "Failed to leave room %q: %v", arg, err)
			} else {
				pe.sendNotice(ctx, "Left room %q", arg)
			}
		}
	case "!powerlevel", "!pl":
		if len(args) < 1 {
			pe.sendNotice(ctx, "Usage: `!powerlevel <room> <key> <level>`")
			return
		}
		room := pe.resolveRoom(ctx, args[0])
		if room == "" {
			return
		}
		key := args[1]
		level, err := strconv.Atoi(args[2])
		if err != nil {
			pe.sendNotice(ctx, "Invalid power level `%s`: %v", args[2], err)
			return
		}
		var pls event.PowerLevelsEventContent
		err = pe.Bot.Client.StateEvent(ctx, room, event.StatePowerLevels, "", &pls)
		if err != nil {
			pe.sendNotice(ctx, "Failed to get power levels in `%s`: %v", room, err)
			return
		}
		switch strings.ToLower(key) {
		case "invite":
			pls.InvitePtr = &level
		case "kick":
			pls.KickPtr = &level
		case "ban":
			pls.BanPtr = &level
		case "redact":
			pls.RedactPtr = &level
		case "users_default", "users":
			pls.UsersDefault = level
		case "state_default", "state":
			pls.StateDefaultPtr = &level
		case "events_default", "events":
			pls.EventsDefault = level
		case "room", "notifications.room":
			pls.Notifications.RoomPtr = &level
		default:
			if strings.HasPrefix(key, "@") {
				pls.SetUserLevel(id.UserID(key), level)
			} else if strings.ContainsRune(key, '.') {
				if pls.Events == nil {
					pls.Events = make(map[string]int)
				}
				pls.Events[key] = level
			} else {
				pe.sendNotice(ctx, "Invalid power level key `%s`", key)
				return
			}
		}
		_, err = pe.Bot.Client.SendStateEvent(ctx, room, event.StatePowerLevels, "", &pls)
		if err != nil {
			pe.sendNotice(ctx, "Failed to set power levels in `%s`: %v", room, err)
			return
		}
		pe.sendSuccessReaction(ctx, evt.ID)
	case "!redact":
		if len(args) < 1 {
			pe.sendNotice(ctx, "Usage: `!redact <event link or user ID> [reason]`")
			return
		}
		var target *id.MatrixURI
		var err error
		if args[0][0] == '@' {
			target = &id.MatrixURI{
				Sigil1: '@',
				MXID1:  args[0],
			}
		} else {
			target, err = id.ParseMatrixURIOrMatrixToURL(args[0])
			if err != nil {
				pe.sendNotice(ctx, "Failed to parse `%s`: %v", args[0], err)
				return
			}
		}
		reason := strings.Join(args[1:], " ")
		if target.Sigil1 == '@' {
			pe.RedactUser(ctx, target.UserID(), reason, false)
		} else if target.Sigil1 == '!' && target.Sigil2 == '$' {
			_, err = pe.Bot.RedactEvent(ctx, target.RoomID(), target.EventID(), mautrix.ReqRedact{Reason: reason})
			if err != nil {
				pe.sendNotice(ctx, "Failed to redact event `%s`: %v", target.EventID(), err)
				return
			}
		} else {
			pe.sendNotice(ctx, "Invalid target `%s` (must be a user ID or event link)", args[0])
			return
		}
		pe.sendSuccessReaction(ctx, evt.ID)
	case "!redact-recent":
		if len(args) < 2 {
			pe.sendNotice(ctx, "Usage: `!redact-recent <room ID> <since duration> [reason]`")
			return
		}
		room := pe.resolveRoom(ctx, args[0])
		if room == "" {
			return
		}
		since, err := time.ParseDuration(args[1])
		if err != nil {
			pe.sendNotice(ctx, "Invalid duration `%s`: %v", args[1], err)
			return
		}
		reason := strings.Join(args[2:], " ")
		redactedCount, err := pe.redactRecentMessages(ctx, room, since, reason)
		if err != nil {
			pe.sendNotice(ctx, "Failed to redact recent messages: %v", err)
			return
		}
		pe.sendNotice(ctx, "Redacted %d messages", redactedCount)
		pe.sendSuccessReaction(ctx, evt.ID)
	case "!kick":
		if len(args) < 1 {
			pe.sendNotice(ctx, "Usage: `!kick <user ID> [reason]`")
			return
		}
		ignoreUserLimit := args[0] == "--force"
		if ignoreUserLimit {
			args = args[1:]
		}
		pattern := glob.Compile(args[0])
		reason := strings.Join(args[1:], " ")
		users := slices.Collect(pe.findMatchingUsers(pattern, nil))
		if len(users) > 10 && !ignoreUserLimit {
			// TODO replace the force flag with a reaction confirmation
			pe.sendNotice(ctx, "%d users matching `%s` found, use `--force` to kick all of them.", len(users), args[0])
			return
		}
		for _, userID := range users {
			successCount := 0
			rooms := pe.getRoomsUserIsIn(userID)
			if len(rooms) == 0 {
				continue
			}
			roomStrings := make([]string, len(rooms))
			for i, room := range rooms {
				roomStrings[i] = fmt.Sprintf("[%s](%s)", room, room.URI().MatrixToURL())
				var err error
				if !pe.DryRun {
					_, err = pe.Bot.KickUser(ctx, room, &mautrix.ReqKickUser{
						Reason: reason,
						UserID: userID,
					})
				}
				if err != nil {
					pe.sendNotice(ctx, "Failed to kick `%s` from `%s`: %v", userID, room, err)
				} else {
					successCount++
				}
			}
			pe.sendNotice(ctx, "Kicked `%s` from %d rooms: %s", userID, successCount, strings.Join(roomStrings, ", "))
		}
		if len(users) == 0 {
			pe.sendNotice(ctx, "No users matching `%s` found in any rooms", args[0])
			return
		}
		pe.sendSuccessReaction(ctx, evt.ID)
	case "!ban", "!takedown":
		if len(args) < 2 {
			pe.sendNotice(ctx, "Usage: `%s [--hash] <list shortcode> <entity> [reason]`", cmd)
			return
		}
		hash := args[0] == "--hash"
		if hash {
			args = args[1:]
		}
		list := pe.FindListByShortcode(args[0])
		if list == nil {
			pe.sendNotice(ctx, `List %q not found`, args[0])
			return
		}
		target := args[1]
		entityType, ok := validateEntity(target)
		if !ok {
			pe.sendNotice(ctx, "Invalid entity `%s`", target)
			return
		}
		match := pe.Store.MatchExact(pe.GetWatchedLists(), entityType, target)
		if rec := match.Recommendations().BanOrUnban; rec != nil && rec.Recommendation == event.PolicyRecommendationUnban {
			pe.sendNotice(ctx, "`%s` has an unban recommendation: %s", target, rec.Reason)
			return
		}
		var existingStateKey string
		for _, policy := range match {
			if policy.RoomID == list.RoomID && policy.Entity == target {
				existingStateKey = policy.StateKey
			}
		}
		policy := &event.ModPolicyContent{
			Entity:         target,
			Reason:         strings.Join(args[2:], " "),
			Recommendation: event.PolicyRecommendationBan,
		}
		if hash {
			targetHash := util.SHA256String(target)
			policy.UnstableHashes = &event.PolicyHashes{
				SHA256: base64.StdEncoding.EncodeToString(targetHash[:]),
			}
			policy.Entity = ""
		}
		if cmd == "!takedown" || cmd == "!takedown-user" {
			policy.Recommendation = event.PolicyRecommendationUnstableTakedown
			policy.Reason = ""
		}
		resp, err := pe.SendPolicy(ctx, list.RoomID, entityType, existingStateKey, target, policy)
		if err != nil {
			pe.sendNotice(ctx, `Failed to send ban policy: %v`, err)
			return
		}
		zerolog.Ctx(ctx).Info().
			Stringer("policy_list", list.RoomID).
			Any("policy", policy).
			Stringer("policy_event_id", resp.EventID).
			Msg("Sent ban policy from command")
		pe.sendSuccessReaction(ctx, evt.ID)
	case "!remove-ban", "!remove-unban", "!remove-policy":
		if len(args) < 2 {
			pe.sendNotice(ctx, "Usage: `!remove-policy <list> <entity>`")
			return
		}
		list := pe.FindListByShortcode(args[0])
		if list == nil {
			pe.sendNotice(ctx, `List %q not found`, args[0])
			return
		}
		target := args[1]
		entityType, ok := validateEntity(target)
		if !ok {
			pe.sendNotice(ctx, "Invalid entity `%s`", target)
			return
		}
		var existingStateKey string
		match := pe.Store.MatchExact([]id.RoomID{list.RoomID}, entityType, target)
		if len(match) == 0 {
			pe.sendNotice(ctx, "No rule banning `%s` found in [%s](%s)", target, list.Name, list.RoomID.URI().MatrixToURL())
			return
		}
		if rec := match.Recommendations().BanOrUnban; rec != nil {
			existingStateKey = rec.StateKey
			// TODO: handle wildcards and multiple matches, etc
			if cmd == "!remove-unban" && rec.Recommendation != event.PolicyRecommendationUnban {
				pe.sendNotice(ctx, "`%s` does not have an unban recommendation", target)
				return
			} else if cmd == "!remove-ban" && rec.Recommendation != event.PolicyRecommendationBan {
				pe.sendNotice(ctx, "`%s` does not have a ban recommendation", target)
				return
			}
		}
		policy := &event.ModPolicyContent{}
		resp, err := pe.SendPolicy(ctx, list.RoomID, entityType, existingStateKey, target, policy)
		if err != nil {
			pe.sendNotice(ctx, `Failed to remove policy: %v`, err)
			return
		}
		zerolog.Ctx(ctx).Info().
			Stringer("policy_list", list.RoomID).
			Any("policy", policy).
			Stringer("policy_event_id", resp.EventID).
			Msg("Removed policy from command")
		pe.sendSuccessReaction(ctx, evt.ID)
	case "!add-unban":
		if len(args) < 2 {
			pe.sendNotice(ctx, "Usage: `!add-unban <list shortcode> <entity> <reason>`")
			return
		}
		list := pe.FindListByShortcode(args[0])
		if list == nil {
			pe.sendNotice(ctx, `List %q not found`, args[0])
			return
		}
		target := args[1]
		var match policylist.Match
		var entityType policylist.EntityType
		if !strings.HasPrefix(target, "@") {
			entityType = policylist.EntityTypeServer
			match = pe.Store.MatchServer(pe.GetWatchedLists(), target)
		} else {
			entityType = policylist.EntityTypeUser
			match = pe.Store.MatchUser(pe.GetWatchedLists(), id.UserID(target))
		}
		var existingStateKey string
		if rec := match.Recommendations().BanOrUnban; rec != nil {
			if rec.Recommendation == event.PolicyRecommendationUnban {
				pe.sendNotice(ctx, "`%s` already has an unban recommendation: %s", target, rec.Reason)
				return
			} else if rec.RoomID == list.RoomID {
				existingStateKey = rec.StateKey
			}
		}
		policy := &event.ModPolicyContent{
			Entity:         target,
			Reason:         strings.Join(args[2:], " "),
			Recommendation: event.PolicyRecommendationUnban,
		}
		resp, err := pe.SendPolicy(ctx, list.RoomID, entityType, existingStateKey, target, policy)
		if err != nil {
			pe.sendNotice(ctx, `Failed to send unban policy: %v`, err)
			return
		}
		zerolog.Ctx(ctx).Info().
			Stringer("policy_list", list.RoomID).
			Any("policy", policy).
			Stringer("policy_event_id", resp.EventID).
			Msg("Sent unban policy from command")
		pe.sendSuccessReaction(ctx, evt.ID)
	case "!match":
		target := args[0]
		targetUser := id.UserID(target)
		userIDHash, ok := util.DecodeBase64Hash(target)
		if ok {
			targetUser, ok = pe.getUserIDFromHash(*userIDHash)
			if !ok {
				pe.sendNotice(ctx, "No user found for hash `%s`", target)
				return
			}
			target = targetUser.String()
			pe.sendNotice(ctx, "Matched user `%s` for hash `%s`", targetUser, target)
		}
		entityType, _ := validateEntity(target)
		var dur time.Duration
		var match policylist.Match
		if entityType == policylist.EntityTypeUser {
			start := time.Now()
			match = pe.Store.MatchUser(nil, targetUser)
			dur = time.Since(start)
			rooms := pe.getRoomsUserIsIn(targetUser)
			if len(rooms) > 0 {
				formattedRooms := make([]string, len(rooms))
				pe.protectedRoomsLock.RLock()
				for i, roomID := range rooms {
					name := roomID.String()
					meta := pe.protectedRooms[roomID]
					if meta != nil && meta.Name != "" {
						name = meta.Name
					}
					formattedRooms[i] = fmt.Sprintf("* [%s](%s)", name, roomID.URI().MatrixToURL())
				}
				pe.protectedRoomsLock.RUnlock()
				pe.sendNotice(ctx, "User is in %d protected rooms:\n\n%s", len(rooms), strings.Join(formattedRooms, "\n"))
			}
		} else if entityType == policylist.EntityTypeRoom {
			start := time.Now()
			match = pe.Store.MatchRoom(nil, id.RoomID(target))
			dur = time.Since(start)
		} else if entityType == policylist.EntityTypeServer {
			start := time.Now()
			match = pe.Store.MatchServer(nil, target)
			dur = time.Since(start)
		} else {
			pe.sendNotice(ctx, "Invalid entity `%s`", target)
			return
		}
		if match != nil {
			eventStrings := make([]string, len(match))
			for i, policy := range match {
				policyRoomName := policy.RoomID.String()
				if meta := pe.GetWatchedListMeta(policy.RoomID); meta != nil {
					policyRoomName = meta.Name
				}
				eventStrings[i] = fmt.Sprintf("* [%s] [%s](%s) set recommendation `%s` for `%s` at %s for %s",
					policyRoomName, policy.Sender, policy.Sender.URI().MatrixToURL(), policy.Recommendation, policy.EntityOrHash(), time.UnixMilli(policy.Timestamp), policy.Reason)
			}
			pe.sendNotice(ctx, "Matched in %s with recommendations %+v\n\n%s", dur, match.Recommendations(), strings.Join(eventStrings, "\n"))
		} else {
			pe.sendNotice(ctx, "No match in %s", dur.String())
		}
	case "!send-as-bot":
		if len(args) < 2 {
			pe.sendNotice(ctx, "Usage: `!send-as-bot <room ID> <message>`")
			return
		}
		target := pe.resolveRoom(ctx, args[0])
		if target == "" {
			return
		}
		resp, err := pe.Bot.SendMessageEvent(ctx, target, event.EventMessage, &event.MessageEventContent{
			MsgType: event.MsgText,
			Body:    strings.Join(args[1:], " "),
		})
		if err != nil {
			pe.sendNotice(ctx, "Failed to send message to [%s](%s): %v", target, target.URI().MatrixToURL(), err)
		} else {
			pe.sendNotice(ctx, "Sent message to [%s](%s): [%s](%s)", target, target.URI().MatrixToURL(), resp.EventID, target.EventURI(resp.EventID).MatrixToURL())
		}
	case "!help", "!meowlnir":
		if len(args) == 0 {
			pe.sendNotice(ctx, "Available commands:\n"+
				"* `!join <rooms...>` - Join a room\n"+
				"* `!knock <rooms...>` - Ask to join a room\n"+
				"* `!leave <rooms...>` - Leave a room\n"+
				"* `!powerlevel <room> <key> <level>` - Set a power level\n"+
				"* `!redact <event link or user ID> [reason]` - Redact all messages from a user\n"+
				"* `!redact-recent <room> <since duration> [reason]` - Redact all recent messages in a room\n"+
				"* `!kick <user ID> [reason]` - Kick a user from all rooms\n"+
				"* `!ban [--hash] <list shortcode> <entity> [reason]` - Add a ban policy\n"+
				"* `!takedown [--hash] <list shortcode> <entity>` - Add a takedown policy\n"+
				"* `!remove-ban <list shortcode> <entity>` - Remove a ban policy\n"+
				"* `!add-unban <list shortcode> <entity> [reason]` - Add a ban exclusion policy\n"+
				"* `!match <entity>` - Match an entity against all lists\n"+
				"* `!send-as-bot <room> <message>` - Send a message as the bot\n"+
				// "* `!help <command>` - Show detailed help for a command\n" +
				"* `!help` - Show this help message\n"+
				"\n"+
				"All fields that want a room will accept both room IDs and aliases.\n",
			)
		} else {
			switch strings.ToLower(strings.TrimLeft(args[0], "!")) {
			case "join":
				// TODO
			}
		}
	}
}

func (pe *PolicyEvaluator) resolveRoom(ctx context.Context, room string) id.RoomID {
	if strings.HasPrefix(room, "#") {
		resp, err := pe.Bot.ResolveAlias(ctx, id.RoomAlias(room))
		if err != nil {
			zerolog.Ctx(ctx).Warn().Err(err).
				Str("room_input", room).
				Msg("Failed to resolve alias")
			pe.sendNotice(ctx, "Failed to resolve alias `%s`: %v", room, err)
			return ""
		}
		return resp.RoomID
	}
	return id.RoomID(room)
}

var homeserverPatternRegex = regexp.MustCompile(`^[a-zA-Z0-9.*?-]+\.[a-zA-Z0-9*?-]+$`)

func validateEntity(entity string) (policylist.EntityType, bool) {
	if len(entity) == 0 {
		return "", false
	}
	if entity[0] == '@' {
		return policylist.EntityTypeUser, true
	} else if entity[0] == '!' {
		return policylist.EntityTypeRoom, true
	} else if homeserverPatternRegex.MatchString(entity) {
		return policylist.EntityTypeServer, true
	}
	return "", false
}

func (pe *PolicyEvaluator) SendPolicy(ctx context.Context, policyList id.RoomID, entityType policylist.EntityType, stateKey, rawEntity string, content *event.ModPolicyContent) (*mautrix.RespSendEvent, error) {
	if stateKey == "" {
		stateKeyHash := sha256.Sum256(append([]byte(rawEntity), []byte(content.Recommendation)...))
		stateKey = base64.StdEncoding.EncodeToString(stateKeyHash[:])
	}
	return pe.Bot.SendStateEvent(ctx, policyList, entityType.EventType(), stateKey, content)
}

func (pe *PolicyEvaluator) HandleReport(ctx context.Context, senderClient *mautrix.Client, targetUserID id.UserID, roomID id.RoomID, eventID id.EventID, reason string) error {
	sender := senderClient.UserID
	var evt *event.Event
	var err error
	if eventID != "" {
		evt, err = senderClient.GetEvent(ctx, roomID, eventID)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get report target event with user's token")
			pe.sendNotice(
				ctx, `[%s](%s) reported [an event](%s) for %s, but the event could not be fetched: %v`,
				sender, sender.URI().MatrixToURL(), roomID.EventURI(eventID).MatrixToURL(), reason, err,
			)
			return fmt.Errorf("failed to fetch event: %w", err)
		}
		targetUserID = evt.Sender
	}
	if !pe.Admins.Has(sender) || !strings.HasPrefix(reason, "/") || targetUserID == "" {
		if eventID != "" {
			pe.sendNotice(
				ctx, `[%s](%s) reported [an event](%s) from [%s](%s) for %s`,
				sender, sender.URI().MatrixToURL(), roomID.EventURI(eventID).MatrixToURL(),
				evt.Sender, evt.Sender.URI().MatrixToURL(),
				reason,
			)
		} else if roomID != "" {
			pe.sendNotice(
				ctx, `[%s](%s) reported [a room](%s) for %s`,
				sender, sender.URI().MatrixToURL(), roomID.URI().MatrixToURL(),
				reason,
			)
		} else if targetUserID != "" {
			pe.sendNotice(
				ctx, `[%s](%s) reported [%s](%s) for %s`,
				sender, sender.URI().MatrixToURL(), targetUserID.URI().MatrixToURL(),
				reason,
			)
		}
		return nil
	}
	fields := strings.Fields(reason)
	cmd := strings.TrimPrefix(fields[0], "/")
	args := fields[1:]
	switch strings.ToLower(cmd) {
	case "ban":
		if len(args) < 2 {
			return mautrix.MInvalidParam.WithMessage("Not enough arguments for ban")
		}
		match := pe.Store.MatchUser(pe.GetWatchedLists(), targetUserID)
		if rec := match.Recommendations().BanOrUnban; rec != nil {
			if rec.Recommendation == event.PolicyRecommendationUnban {
				return mautrix.RespError{
					ErrCode:    "FI.MAU.MEOWLNIR.UNBAN_RECOMMENDED",
					Err:        fmt.Sprintf("%s has an unban recommendation: %s", targetUserID, rec.Reason),
					StatusCode: http.StatusConflict,
				}
			} else {
				return mautrix.RespError{
					ErrCode:    "FI.MAU.MEOWLNIR.ALREADY_BANNED",
					Err:        fmt.Sprintf("%s is already banned for: %s", targetUserID, rec.Reason),
					StatusCode: http.StatusConflict,
				}
			}
		}
		list := pe.FindListByShortcode(args[0])
		if list == nil {
			pe.sendNotice(ctx, `Failed to handle [%s](%s)'s report of [%s](%s): list %q not found`,
				sender, sender.URI().MatrixToURL(), targetUserID, targetUserID.URI().MatrixToURL(), args[0])
			return mautrix.MNotFound.WithMessage(fmt.Sprintf("List with shortcode %q not found", args[0]))
		}
		policy := &event.ModPolicyContent{
			Entity:         string(targetUserID),
			Reason:         strings.Join(args[1:], " "),
			Recommendation: event.PolicyRecommendationBan,
		}
		resp, err := pe.SendPolicy(ctx, list.RoomID, policylist.EntityTypeUser, "", string(targetUserID), policy)
		if err != nil {
			pe.sendNotice(ctx, `Failed to handle [%s](%s)'s report of [%s](%s) for %s ([%s](%s)): %v`,
				sender, sender.URI().MatrixToURL(), targetUserID, targetUserID.URI().MatrixToURL(),
				list.Name, list.RoomID, list.RoomID.URI().MatrixToURL(), err)
			return fmt.Errorf("failed to send policy: %w", err)
		}
		zerolog.Ctx(ctx).Info().
			Stringer("policy_list", list.RoomID).
			Any("policy", policy).
			Stringer("policy_event_id", resp.EventID).
			Msg("Sent ban policy from report")
		pe.sendNotice(ctx, `Processed [%s](%s)'s report of [%s](%s) and sent a ban policy to %s ([%s](%s)) for %s`,
			sender, sender.URI().MatrixToURL(), targetUserID, targetUserID.URI().MatrixToURL(),
			list.Name, list.RoomID, list.RoomID.URI().MatrixToURL(), policy.Reason)
	}
	return nil
}
