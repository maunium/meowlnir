package policyeval

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/glob"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/commands"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/synapseadmin"

	"go.mau.fi/meowlnir/config"
	"go.mau.fi/meowlnir/policylist"
	"go.mau.fi/meowlnir/util"
)

type CommandEvent = commands.Event[*PolicyEvaluator]
type CommandHandler = commands.Handler[*PolicyEvaluator]

const SuccessReaction = "✅"

func (pe *PolicyEvaluator) HandleCommand(ctx context.Context, evt *event.Event) {
	if !evt.Mautrix.WasEncrypted && pe.Bot.CryptoHelper != nil {
		zerolog.Ctx(ctx).Warn().
			Stringer("event_id", evt.ID).
			Stringer("sender", evt.Sender).
			Msg("Dropping unencrypted command event")
		return
	} else if evt.Mautrix.WasEncrypted && evt.Mautrix.TrustState < id.TrustStateCrossSignedTOFU {
		zerolog.Ctx(ctx).Warn().
			Stringer("event_id", evt.ID).
			Stringer("sender", evt.Sender).
			Stringer("trust_state", evt.Mautrix.TrustState).
			Msg("Dropping encrypted event with insufficient trust state")
		return
	}
	pe.commandProcessor.Process(ctx, evt)
}

func (pe *PolicyEvaluator) HandleReaction(ctx context.Context, evt *event.Event) {
	pe.commandProcessor.Process(ctx, evt)
}

var cmdJoin = &CommandHandler{
	Name: "join",
	Func: func(ce *CommandEvent) {
		if len(ce.Args) == 0 {
			ce.Reply("Usage: `!join <room ID>...`")
			return
		}
		for _, arg := range ce.Args {
			joinIdentifier, via := resolveRoomIDOrAlias(ce, arg)
			if joinIdentifier == "" {
				continue
			}
			_, err := ce.Meta.Bot.JoinRoom(ce.Ctx, joinIdentifier, &mautrix.ReqJoinRoom{
				Via: via,
			})
			if err != nil {
				ce.Reply("Failed to join room %s: %v", format.SafeMarkdownCode(arg), err)
			} else {
				ce.Reply("Joined room %s", format.SafeMarkdownCode(arg))
			}
		}
		ce.React(SuccessReaction)
	},
}

var cmdKnock = &CommandHandler{
	Name: "knock",
	Func: func(ce *CommandEvent) {
		if len(ce.Args) == 0 {
			ce.Reply("Usage: `!knock <rooms...>`")
			return
		}
		for _, arg := range ce.Args {
			joinIdentifier, via := resolveRoomIDOrAlias(ce, arg)
			if joinIdentifier == "" {
				continue
			}
			_, err := ce.Meta.Bot.KnockRoom(ce.Ctx, joinIdentifier, &mautrix.ReqKnockRoom{
				Via: via,
			})
			if err != nil {
				ce.Reply("Failed to knock on room %s: %v", format.SafeMarkdownCode(arg), err)
			} else {
				ce.Reply("Requested to join room %s", format.SafeMarkdownCode(arg))
			}
		}
		ce.React(SuccessReaction)
	},
}

var cmdLeave = &CommandHandler{
	Name: "leave",
	Func: func(ce *CommandEvent) {
		if len(ce.Args) == 0 {
			ce.Reply("Usage: `!leave <room ID>...`")
			return
		}
		for _, arg := range ce.Args {
			target := resolveRoom(ce, arg)
			if target == "" {
				continue
			}
			_, err := ce.Meta.Bot.LeaveRoom(ce.Ctx, target)
			if err != nil {
				ce.Reply("Failed to leave room %s: %v", format.SafeMarkdownCode(arg), err)
			} else {
				ce.Reply("Left room %s", format.SafeMarkdownCode(arg))
			}
		}
	},
}

var cmdPowerLevel = &CommandHandler{
	Name:    "powerlevel",
	Aliases: []string{"pl"},
	Func: func(ce *CommandEvent) {

		if len(ce.Args) < 1 {
			ce.Reply("Usage: `!powerlevel <room|all> <key> <level>`")
			return
		}
		var rooms []id.RoomID
		if ce.Args[0] == "all" {
			rooms = ce.Meta.GetProtectedRooms()
		} else {
			room := resolveRoom(ce, ce.Args[0])
			if room == "" {
				return
			}
			rooms = []id.RoomID{room}
		}
		key := ce.Args[1]
		level, err := strconv.Atoi(ce.Args[2])
		if err != nil {
			ce.Reply("Invalid power level %s: %v", format.SafeMarkdownCode(ce.Args[2]), err)
			return
		}
		for _, room := range rooms {
			var pls event.PowerLevelsEventContent
			// No need to fetch the create event here, this is a manual update that is allowed to fail if the user holds it wrong
			err = ce.Meta.Bot.Client.StateEvent(ce.Ctx, room, event.StatePowerLevels, "", &pls)
			if err != nil {
				ce.Reply("Failed to get power levels in %s: %v", format.SafeMarkdownCode(room), err)
				return
			}
			const MagicUnsetValue = -1644163703
			var oldLevel int
			switch strings.ToLower(key) {
			case "invite":
				oldLevel = pls.Invite()
				pls.InvitePtr = &level
			case "kick":
				oldLevel = pls.Kick()
				pls.KickPtr = &level
			case "ban":
				oldLevel = pls.Ban()
				pls.BanPtr = &level
			case "redact":
				oldLevel = pls.Redact()
				pls.RedactPtr = &level
			case "users_default", "users":
				oldLevel = pls.UsersDefault
				pls.UsersDefault = level
			case "state_default", "state":
				oldLevel = pls.StateDefault()
				pls.StateDefaultPtr = &level
			case "events_default", "events":
				oldLevel = pls.EventsDefault
				pls.EventsDefault = level
			case "room", "notifications.room":
				oldLevel = pls.Notifications.Room()
				pls.Notifications.RoomPtr = &level
			default:
				if strings.HasPrefix(key, "@") {
					oldLevel = pls.GetUserLevel(id.UserID(key))
					pls.SetUserLevel(id.UserID(key), level)
				} else if strings.ContainsRune(key, '.') {
					if pls.Events == nil {
						pls.Events = make(map[string]int)
					}
					var ok bool
					oldLevel, ok = pls.Events[key]
					if !ok {
						oldLevel = MagicUnsetValue
					}
					pls.Events[key] = level
				} else {
					ce.Reply("Invalid power level key %s", format.SafeMarkdownCode(key))
					return
				}
			}
			if oldLevel == level && oldLevel != MagicUnsetValue {
				ce.Reply(
					"Power level for %s in %s is already set to %s",
					format.SafeMarkdownCode(key),
					format.SafeMarkdownCode(room),
					format.SafeMarkdownCode(strconv.Itoa(level)),
				)
				continue
			}
			_, err = ce.Meta.Bot.Client.SendStateEvent(ce.Ctx, room, event.StatePowerLevels, "", &pls)
			if err != nil {
				ce.Reply("Failed to set power levels in %s: %v", format.SafeMarkdownCode(room), err)
				continue
			}
		}
		ce.React(SuccessReaction)
	},
}

var cmdRedact = &CommandHandler{
	Name: "redact",
	Func: func(ce *CommandEvent) {
		if len(ce.Args) < 1 {
			ce.Reply("Usage: `!redact <event link or user ID> [reason]`")
			return
		}
		var target *id.MatrixURI
		var err error
		if ce.Args[0][0] == '@' {
			target = &id.MatrixURI{
				Sigil1: '@',
				MXID1:  ce.Args[0][1:],
			}
		} else {
			target, err = id.ParseMatrixURIOrMatrixToURL(ce.Args[0])
			if err != nil {
				ce.Reply("Failed to parse %s: %v", format.SafeMarkdownCode(ce.Args[0]), err)
				return
			}
		}
		reason := strings.Join(ce.Args[1:], " ")
		if target.Sigil1 == '@' {
			ce.Meta.RedactUser(ce.Ctx, target.UserID(), reason, false)
		} else if target.Sigil1 == '!' && target.Sigil2 == '$' {
			_, err = ce.Meta.Bot.RedactEvent(ce.Ctx, target.RoomID(), target.EventID(), mautrix.ReqRedact{Reason: reason})
			if err != nil {
				ce.Reply("Failed to redact event %s: %v", format.SafeMarkdownCode(target.EventID()), err)
				return
			}
		} else {
			ce.Reply("Invalid target %s (must be a user ID or event link)", format.SafeMarkdownCode(ce.Args[0]))
			return
		}
		ce.React(SuccessReaction)
	},
}

var cmdRedactRecent = &CommandHandler{
	Name: "redact-recent",
	Func: func(ce *CommandEvent) {
		if len(ce.Args) < 2 {
			ce.Reply("Usage: `!redact-recent <room ID> <since duration> [reason]`")
			return
		}
		room := resolveRoom(ce, ce.Args[0])
		if room == "" {
			return
		}
		since, err := time.ParseDuration(ce.Args[1])
		if err != nil {
			ce.Reply("Invalid duration %s: %v", format.SafeMarkdownCode(ce.Args[1]), err)
			return
		}
		reason := strings.Join(ce.Args[2:], " ")
		redactedCount, err := ce.Meta.redactRecentMessages(ce.Ctx, room, "", since, false, reason)
		if err != nil {
			ce.Reply("Failed to redact recent messages: %v", err)
			return
		}
		ce.Reply("Redacted %d messages", redactedCount)
		ce.React(SuccessReaction)
	},
}

var cmdKick = &CommandHandler{
	Name: "kick",
	Func: func(ce *CommandEvent) {
		if len(ce.Args) < 1 {
			ce.Reply("Usage: `!kick [--force] [--room <room ID>] <user ID> [reason]`")
			return
		}
		ignoreUserLimit := ce.Args[0] == "--force"
		if ignoreUserLimit {
			ce.Args = ce.Args[1:]
		}
		var targetRoom id.RoomID
		if ce.Args[0] == "--room" && len(ce.Args) >= 2 {
			targetRoom = resolveRoom(ce, ce.Args[1])
			if targetRoom == "" {
				return
			}
			ce.Args = ce.Args[2:]
		}
		pattern := glob.Compile(ce.Args[0])
		reason := strings.Join(ce.Args[1:], " ")
		users := slices.Collect(ce.Meta.findMatchingUsers(pattern, nil, true))
		if len(users) > 10 && !ignoreUserLimit {
			// TODO replace the force flag with a reaction confirmation
			ce.Reply("%d users matching %s found, use `--force` to kick all of them.", len(users), format.SafeMarkdownCode(ce.Args[0]))
			return
		}
		for _, userID := range users {
			successCount := 0
			var rooms []id.RoomID
			if targetRoom != "" {
				rooms = ce.Meta.getRoomsUserIsIn(userID)
				if len(rooms) == 0 {
					continue
				}
			} else {
				rooms = []id.RoomID{targetRoom}
			}
			roomStrings := make([]string, len(rooms))
			for i, room := range rooms {
				roomStrings[i] = fmt.Sprintf("[%s](%s)", room, room.URI().MatrixToURL())
				var err error
				if !ce.Meta.DryRun {
					_, err = ce.Meta.Bot.KickUser(ce.Ctx, room, &mautrix.ReqKickUser{
						Reason: reason,
						UserID: userID,
					})
				}
				if err != nil {
					ce.Reply("Failed to kick %s from %s: %v", format.SafeMarkdownCode(userID), format.SafeMarkdownCode(room), err)
				} else {
					successCount++
				}
			}
			ce.Reply("Kicked %s from %d rooms: %s", format.SafeMarkdownCode(userID), successCount, strings.Join(roomStrings, ", "))
		}
		if len(users) == 0 {
			ce.Reply("No users matching %s found in any rooms", format.SafeMarkdownCode(ce.Args[0]))
			return
		}
		ce.React(SuccessReaction)
	},
}

func (pe *PolicyEvaluator) deduplicatePolicy(
	ce *CommandEvent,
	list *config.WatchedPolicyList,
	policy *event.ModPolicyContent,
	entityType policylist.EntityType,
) (existingStateKey string, ok bool) {
	match := ce.Meta.Store.MatchExact([]id.RoomID{list.RoomID}, entityType, policy.Entity)
	rec := match.Recommendations().BanOrUnban
	if rec == nil {
		return "", true
	} else if rec.Recommendation == policy.Recommendation && rec.EntityOrHash() == policy.EntityOrHash() {
		if rec.Reason == policy.Reason {
			ce.Reply(
				"%s already has a %s recommendation in [%s](%s) for %s (sent by [%s](%s) at %s)",
				format.SafeMarkdownCode(policy.EntityOrHash()),
				format.SafeMarkdownCode(rec.Recommendation),
				format.EscapeMarkdown(list.Name),
				list.RoomID.URI(ce.Meta.Bot.ServerName).MatrixToURL(),
				format.SafeMarkdownCode(rec.Reason),
				format.EscapeMarkdown(rec.Sender.String()),
				rec.Sender.URI().MatrixToURL(),
				time.UnixMilli(rec.Timestamp).String(),
			)
			return "", false
		} else {
			return rec.StateKey, true
		}
	} else if (policy.Recommendation != event.PolicyRecommendationUnban && rec.Recommendation == event.PolicyRecommendationUnban) ||
		(policy.Recommendation == event.PolicyRecommendationUnban && rec.Recommendation != event.PolicyRecommendationUnban) {
		ce.Reply(
			"%s has a conflicting %s recommendation for %s (sent by [%s](%s) at %s)",
			format.SafeMarkdownCode(policy.EntityOrHash()),
			format.SafeMarkdownCode(rec.Recommendation),
			format.SafeMarkdownCode(rec.Reason),
			format.EscapeMarkdown(rec.Sender.String()),
			rec.Sender.URI().MatrixToURL(),
			time.UnixMilli(rec.Timestamp).String(),
		)
		return "", false
	} else {
		return "", true
	}
}

var cmdBan = &CommandHandler{
	Name:    "ban",
	Aliases: []string{"takedown"},
	Func: func(ce *CommandEvent) {
		if len(ce.Args) < 2 {
			ce.Reply("Usage: `%s [--hash] <list shortcode> <entity> [reason]`", ce.Command)
			return
		}
		hash := ce.Args[0] == "--hash"
		if hash {
			ce.Args = ce.Args[1:]
		}
		list := ce.Meta.FindListByShortcode(ce.Args[0])
		if list == nil {
			ce.Reply("List %s not found", format.SafeMarkdownCode(ce.Args[0]))
			return
		}
		entity, entityType, ok := resolveEntity(ce, ce.Args[1])
		if !ok {
			return
		}
		policy := &event.ModPolicyContent{
			Entity:         entity,
			Reason:         strings.Join(ce.Args[2:], " "),
			Recommendation: event.PolicyRecommendationBan,
		}
		if hash {
			targetHash := util.SHA256String(policy.Entity)
			policy.UnstableHashes = &event.PolicyHashes{
				SHA256: base64.StdEncoding.EncodeToString(targetHash[:]),
			}
		}
		if ce.Command == "takedown" {
			policy.Recommendation = event.PolicyRecommendationUnstableTakedown
		}
		existingStateKey, ok := ce.Meta.deduplicatePolicy(ce, list, policy, entityType)
		if !ok {
			return
		}
		target := policy.Entity
		if hash {
			policy.Entity = ""
		}
		resp, err := ce.Meta.SendPolicy(ce.Ctx, list.RoomID, entityType, existingStateKey, target, policy)
		if err != nil {
			ce.Reply("Failed to send ban policy: %v", err)
			return
		}
		ce.Log.Info().
			Stringer("policy_list", list.RoomID).
			Any("policy", policy).
			Stringer("policy_event_id", resp.EventID).
			Msg("Sent ban policy from command")
		ce.React(SuccessReaction)
	},
}

var cmdRemovePolicy = &CommandHandler{
	Name:    "remove-policy",
	Aliases: []string{"remove-ban", "remove-unban"},
	Func: func(ce *CommandEvent) {
		if len(ce.Args) < 2 {
			ce.Reply("Usage: `!remove-policy <list> <entity>`")
			return
		}
		list := ce.Meta.FindListByShortcode(ce.Args[0])
		if list == nil {
			ce.Reply("List %s not found", format.SafeMarkdownCode(ce.Args[0]))
			return
		}
		target, entityType, ok := resolveEntity(ce, ce.Args[1])
		if !ok {
			return
		}
		var existingStateKey string
		var match policylist.Match
		if hashEntity, ok := util.DecodeBase64Hash(target); ok {
			match = ce.Meta.Store.MatchHash([]id.RoomID{list.RoomID}, entityType, *hashEntity)
		} else {
			match = ce.Meta.Store.MatchExact([]id.RoomID{list.RoomID}, entityType, target)
		}
		if len(match) == 0 {
			ce.Reply("No rule banning %s found in [%s](%s)", format.SafeMarkdownCode(target), format.EscapeMarkdown(list.Name), list.RoomID.URI().MatrixToURL())
			return
		}
		if rec := match.Recommendations().BanOrUnban; rec != nil {
			existingStateKey = rec.StateKey
			// TODO: handle wildcards and multiple matches, etc
			if ce.Command == "remove-unban" && rec.Recommendation != event.PolicyRecommendationUnban {
				ce.Reply("%s does not have an unban recommendation", format.SafeMarkdownCode(target))
				return
			} else if ce.Command == "remove-ban" && rec.Recommendation != event.PolicyRecommendationBan {
				ce.Reply("%s does not have a ban recommendation", format.SafeMarkdownCode(target))
				return
			}
		}
		resp, err := ce.Meta.Bot.SendStateEvent(ce.Ctx, list.RoomID, entityType.EventType(), existingStateKey, json.RawMessage("{}"))
		if err != nil {
			ce.Reply("Failed to remove policy: %v", err)
			return
		}
		ce.Log.Info().
			Stringer("policy_list", list.RoomID).
			Stringer("policy_event_id", resp.EventID).
			Msg("Removed policy from command")
		ce.React(SuccessReaction)
	},
}

var cmdAddUnban = &CommandHandler{
	Name: "add-unban",
	Func: func(ce *CommandEvent) {
		if len(ce.Args) < 2 {
			ce.Reply("Usage: `!add-unban <list shortcode> <entity> <reason>`")
			return
		}
		list := ce.Meta.FindListByShortcode(ce.Args[0])
		if list == nil {
			ce.Reply("List %s not found", format.SafeMarkdownCode(ce.Args[0]))
			return
		}
		entity, entityType, ok := resolveEntity(ce, ce.Args[1])
		if !ok {
			return
		}
		policy := &event.ModPolicyContent{
			Entity:         entity,
			Reason:         strings.Join(ce.Args[2:], " "),
			Recommendation: event.PolicyRecommendationUnban,
		}
		existingStateKey, ok := ce.Meta.deduplicatePolicy(ce, list, policy, entityType)
		if !ok {
			return
		}
		resp, err := ce.Meta.SendPolicy(ce.Ctx, list.RoomID, entityType, existingStateKey, policy.Entity, policy)
		if err != nil {
			ce.Reply("Failed to send unban policy: %v", err)
			return
		}
		ce.Log.Info().
			Stringer("policy_list", list.RoomID).
			Any("policy", policy).
			Stringer("policy_event_id", resp.EventID).
			Msg("Sent unban policy from command")
		ce.React(SuccessReaction)
	},
}

func doMatch(ce *CommandEvent, target string) {
	userIDHash, ok := util.DecodeBase64Hash(target)
	if ok {
		targetUser, ok := ce.Meta.getUserIDFromHash(*userIDHash)
		if !ok {
			ce.Reply("No user found for hash %s", format.SafeMarkdownCode(target))
			return
		}
		target = targetUser.String()
		ce.Reply("Matched user %s for hash %s", format.SafeMarkdownCode(targetUser.String()), format.SafeMarkdownCode(target))
	}
	target, entityType, ok := resolveEntity(ce, target)
	if !ok {
		return
	}
	var dur time.Duration
	var match policylist.Match
	if entityType == policylist.EntityTypeUser {
		start := time.Now()
		match = ce.Meta.Store.MatchUser(nil, id.UserID(target))
		dur = time.Since(start)
		rooms := ce.Meta.getRoomsUserIsIn(id.UserID(target))
		if len(rooms) > 0 {
			formattedRooms := make([]string, len(rooms))
			ce.Meta.protectedRoomsLock.RLock()
			for i, roomID := range rooms {
				name := roomID.String()
				meta := ce.Meta.protectedRooms[roomID]
				if meta != nil && meta.Name != "" {
					name = meta.Name
				}
				formattedRooms[i] = fmt.Sprintf("* [%s](%s)", name, roomID.URI().MatrixToURL())
			}
			ce.Meta.protectedRoomsLock.RUnlock()
			ce.Reply("User is in %d protected rooms:\n\n%s", len(rooms), strings.Join(formattedRooms, "\n"))
		}
	} else if entityType == policylist.EntityTypeRoom {
		start := time.Now()
		match = ce.Meta.Store.MatchRoom(nil, id.RoomID(target))
		dur = time.Since(start)
	} else if entityType == policylist.EntityTypeServer {
		start := time.Now()
		match = ce.Meta.Store.MatchServer(nil, target)
		dur = time.Since(start)
	} else {
		ce.Reply("Invalid entity %s", format.SafeMarkdownCode(target))
		return
	}
	if match != nil {
		eventStrings := make([]string, len(match))
		for i, policy := range match {
			policyRoomName := policy.RoomID.String()
			if meta := ce.Meta.GetWatchedListMeta(policy.RoomID); meta != nil {
				policyRoomName = meta.Name
			}
			eventStrings[i] = fmt.Sprintf(
				"* [%s] [%s](%s) set recommendation %s for %s at %s for %s",
				format.EscapeMarkdown(policyRoomName),
				policy.Sender,
				policy.Sender.URI().MatrixToURL(),
				format.SafeMarkdownCode(policy.Recommendation),
				format.SafeMarkdownCode(policy.EntityOrHash()),
				format.EscapeMarkdown(time.UnixMilli(policy.Timestamp).String()),
				format.SafeMarkdownCode(policy.Reason),
			)
		}
		ce.Reply(
			"Matched in %s with recommendation %s\n\n%s",
			dur.String(),
			format.SafeMarkdownCode(match.Recommendations().String()),
			strings.Join(eventStrings, "\n"),
		)
	} else {
		ce.Reply("No match for %s %s in %s", entityType, format.SafeMarkdownCode(target), dur)
	}
}

var cmdMatch = &CommandHandler{
	Name: "match",
	Func: func(ce *CommandEvent) {
		if len(ce.Args) == 0 {
			ce.Reply("Usage: `!match <entity>...`")
			return
		}
		if ce.Args[0] == "--whitespace" {
			doMatch(ce, strings.TrimPrefix(ce.RawArgs, "--whitespace "))
		} else {
			for _, arg := range ce.Args {
				doMatch(ce, arg)
			}
		}
	},
}

var cmdSearch = &CommandHandler{
	Name: "search",
	Func: func(ce *CommandEvent) {
		target := ce.Args[0]
		start := time.Now()
		match := ce.Meta.Store.Search(nil, target)
		dur := time.Since(start)
		if len(match) > 25 {
			ce.Reply("Too many results (%d) in %s, please narrow your search", len(match), dur)
		} else if len(match) > 0 {
			eventStrings := make([]string, len(match))
			for i, policy := range match {
				policyRoomName := policy.RoomID.String()
				if meta := ce.Meta.GetWatchedListMeta(policy.RoomID); meta != nil {
					policyRoomName = meta.Name
				}
				eventStrings[i] = fmt.Sprintf(
					"* [%s] [%s](%s) set recommendation %s for %ss matching %s at %s for %s",
					format.EscapeMarkdown(policyRoomName),
					policy.Sender,
					policy.Sender.URI().MatrixToURL(),
					format.SafeMarkdownCode(policy.Recommendation),
					policy.EntityType,
					format.SafeMarkdownCode(policy.EntityOrHash()),
					format.EscapeMarkdown(time.UnixMilli(policy.Timestamp).String()),
					format.SafeMarkdownCode(policy.Reason),
				)
			}
			ce.Reply("Found %d results in %s:\n\n%s", len(match), dur, strings.Join(eventStrings, "\n"))
		} else {
			ce.Reply("No results in %s", dur)
		}
		if strings.HasPrefix(target, "@") {
			users := slices.Collect(ce.Meta.findMatchingUsers(glob.Compile(target), nil, true))
			if len(users) > 25 {
				ce.Reply("Found %d users matching %s in protected rooms (too many to list)", len(users), format.SafeMarkdownCode(target))
			} else if len(users) > 0 {
				userStrings := make([]string, len(users))
				for i, user := range users {
					userStrings[i] = fmt.Sprintf("* [%s](%s)", user, user.URI().MatrixToURL())
				}
				ce.Meta.sendNotice(
					ce.Ctx, "Found %d users matching %s in protected rooms:\n\n%s",
					len(users),
					format.SafeMarkdownCode(target),
					strings.Join(userStrings, "\n"),
				)
			} else {
				ce.Reply("No users matching %s found in protected rooms", format.SafeMarkdownCode(target))
			}
		}
	},
}

var cmdSendAsBot = &CommandHandler{
	Name: "send-as-bot",
	Func: func(ce *CommandEvent) {
		if len(ce.Args) < 2 {
			ce.Reply("Usage: `!send-as-bot <room ID> <message>`")
			return
		}
		target := resolveRoom(ce, ce.Args[0])
		if target == "" {
			return
		}
		resp, err := ce.Meta.Bot.SendMessageEvent(ce.Ctx, target, event.EventMessage, &event.MessageEventContent{
			MsgType: event.MsgText,
			Body:    strings.Join(ce.Args[1:], " "),
		})
		if err != nil {
			ce.Reply("Failed to send message to [%s](%s): %v", target, target.URI().MatrixToURL(), err)
		} else {
			ce.Reply("Sent message to [%s](%s): [%s](%s)", target, target.URI().MatrixToURL(), resp.EventID, target.EventURI(resp.EventID).MatrixToURL())
		}
	},
}

const roomsHelp = "Available `!rooms` subcommands:\n\n" +
	"* `!rooms list` - List all protected rooms\n" +
	"* `!rooms info <room ID or alias>` - Get information about a room using the Synapse admin API\n" +
	"* `!rooms delete [--async] <room ID>` - Purge a room from the server\n" +
	"* `!rooms block [--async] <room ID>` - Purge and block a room from the server\n" +
	"* `!rooms delete-status <delete ID>` - Get the status of a room deletion (if `--async` was used)\n" +
	"* `!rooms protect <room ID or alias>...` - Start protecting a room.\n" +
	"* `!rooms unprotect <room ID or alias>...` - Stop protecting a room.\n"

var cmdRooms = &CommandHandler{
	Name:    "rooms",
	Aliases: []string{"room"},
	Subcommands: []*CommandHandler{
		cmdListProtectedRooms,
		cmdProtectRoom,
		cmdRoomInfo,
		cmdRoomDelete,
		cmdRoomDeleteStatus,
		commands.MakeUnknownCommandHandler[*PolicyEvaluator]("!"),
	},
	Func: func(ce *commands.Event[*PolicyEvaluator]) {
		ce.Reply(roomsHelp)
	},
}

var cmdListProtectedRooms = &CommandHandler{
	Name: "list",
	Func: func(ce *CommandEvent) {
		var buf strings.Builder
		buf.WriteString("Protected rooms:\n\n")
		ce.Meta.protectedRoomsLock.RLock()
		for roomID, meta := range ce.Meta.protectedRooms {
			_, _ = fmt.Fprintf(&buf, "* [%s](%s) (%s)\n", format.EscapeMarkdown(meta.Name), roomID.URI(ce.Meta.Bot.ServerName).MatrixToURL(), format.SafeMarkdownCode(roomID))
		}
		ce.Meta.protectedRoomsLock.RUnlock()
		ce.Reply(buf.String())
	},
}

const roomInfoFmt = `Room %s (%s)

* Canonical alias: %s
* Creator: %s
* Version: %s
* Members: %d (%d local)`

func formatRoomInfo(info *synapseadmin.RoomInfo) string {
	return fmt.Sprintf(
		roomInfoFmt,
		format.SafeMarkdownCode(info.CanonicalAlias),
		format.EscapeMarkdown(info.Name), format.SafeMarkdownCode(info.RoomID),
		format.MarkdownMention(info.Creator),
		info.Version,
		info.JoinedMembers, info.JoinedLocalMembers,
	)
}

var cmdRoomInfo = &CommandHandler{
	Name: "info",
	Func: func(ce *commands.Event[*PolicyEvaluator]) {
		if len(ce.Args) == 0 {
			ce.Reply("Usage: `!rooms info <room ID or alias>`")
			return
		}
		roomID := resolveRoom(ce, ce.RawArgs)
		if roomID == "" {
			return
		}
		roomInfo, err := ce.Meta.Bot.SynapseAdmin.RoomInfo(ce.Ctx, roomID)
		if err != nil {
			ce.Reply("Failed to get room info: %v", err)
			return
		}
		ce.Reply(formatRoomInfo(roomInfo))
	},
}

func formatDeleteResult(resp synapseadmin.RespDeleteRoomResult) string {
	var parts []string
	if len(resp.KickedUsers) > 10 {
		parts = append(parts, fmt.Sprintf("* Kicked %d users", len(resp.KickedUsers)))
	} else {
		kickedUsers := make([]string, len(resp.KickedUsers))
		for i, user := range resp.KickedUsers {
			kickedUsers[i] = format.MarkdownMention(user)
		}
		parts = append(parts, fmt.Sprintf("* Kicked users: %s", strings.Join(kickedUsers, ", ")))
	}
	if len(resp.FailedToKickUsers) > 0 {
		failedUsers := make([]string, len(resp.FailedToKickUsers))
		for i, user := range resp.FailedToKickUsers {
			failedUsers[i] = format.MarkdownMention(user)
		}
		parts = append(parts, fmt.Sprintf("* Failed to kick users: %s", strings.Join(failedUsers, ", ")))
	}
	if len(resp.LocalAliases) > 0 {
		localAliases := make([]string, len(resp.LocalAliases))
		for i, alias := range resp.LocalAliases {
			localAliases[i] = format.SafeMarkdownCode(alias)
		}
		parts = append(parts, fmt.Sprintf("* Deleted local aliases: %s", strings.Join(localAliases, ", ")))
	}
	return strings.Join(parts, "\n")
}

var cmdRoomDeleteStatus = &CommandHandler{
	Name: "delete-status",
	Func: func(ce *CommandEvent) {
		if len(ce.Args) == 0 {
			ce.Reply("Usage: `!rooms delete-status <delete ID>`")
			return
		}
		resp, err := ce.Meta.Bot.SynapseAdmin.DeleteRoomStatus(ce.Ctx, ce.Args[0])
		if err != nil {
			ce.Reply("Failed to get delete status for %s: %v", format.SafeMarkdownCode(ce.Args[0]), err)
		} else if resp.Status == "complete" {
			ce.Reply("Deletion is complete:\n\n%s", formatDeleteResult(resp.ShutdownRoom))
		} else if resp.Status == "failed" {
			ce.Reply("Deletion failed: %s", resp.Error)
		} else {
			ce.Reply("Deletion is still in progress (%s)", resp.Status)
		}
	},
}

var cmdRoomDelete = &CommandHandler{
	Name:    "delete",
	Aliases: []string{"purge", "block"},
	Func: func(ce *CommandEvent) {
		if len(ce.Args) == 0 {
			ce.Reply("Usage: `!rooms %s [--async] <room ID>`", ce.Command)
			return
		}
		if ce.Args[0] == "--confirm" {
			andBlock := ""
			if ce.Command == "block" {
				andBlock = " and block"
			}
			roomID := strings.TrimPrefix(ce.RawArgs, "--confirm ")
			evtID := ce.Respond(fmt.Sprintf("Really purge%s %s?", andBlock, format.SafeMarkdownCode(roomID)), commands.ReplyOpts{
				Reply:         true,
				AllowMarkdown: true,
				Extra: map[string]any{
					commands.ReactionCommandsKey: map[string]any{
						"/confirm": fmt.Sprintf("!rooms %s %s", ce.Command, roomID),
						"/cancel":  "",
					},
				},
			})
			ce.Meta.sendReactions(ce.Ctx, evtID, "/cancel", "/confirm")
			return
		}
		roomID := id.RoomID(ce.RawArgs)
		if ce.Meta.DryRun {
			ce.Reply("Would have deleted room %s if dry run wasn't enabled", format.SafeMarkdownCode(roomID))
			return
		}
		req := synapseadmin.ReqDeleteRoom{
			Purge: true,
			Block: ce.Command == "block",
		}
		if ce.Args[0] == "--async" {
			roomID = id.RoomID(strings.TrimPrefix(ce.RawArgs, "--async "))
			resp, err := ce.Meta.Bot.SynapseAdmin.DeleteRoom(ce.Ctx, roomID, req)
			if err != nil {
				ce.Reply("Failed to delete room %s: %v", format.SafeMarkdownCode(roomID), err)
			} else {
				ce.Reply("Successfully initiated deletion of room %s: ID %s", format.SafeMarkdownCode(roomID), format.SafeMarkdownCode(resp.DeleteID))
			}
		} else {
			reactionID := ce.React("\u23f3\ufe0f")
			resp, err := ce.Meta.Bot.SynapseAdmin.DeleteRoomSync(ce.Ctx, roomID, req)
			_, _ = ce.Meta.Bot.RedactEvent(ce.Ctx, ce.RoomID, reactionID)
			if err != nil {
				ce.Reply("Failed to delete room %s: %v", format.SafeMarkdownCode(roomID), err)
			} else {
				ce.Reply("Successfully deleted room %s\n\n%s", format.SafeMarkdownCode(roomID), formatDeleteResult(resp))
			}
		}
	},
}

var cmdSuspend = &CommandHandler{
	Name:    "suspend",
	Aliases: []string{"unsuspend"},
	Func: func(ce *CommandEvent) {
		err := ce.Meta.Bot.SynapseAdmin.SuspendAccount(ce.Ctx, id.UserID(ce.Args[0]), synapseadmin.ReqSuspendUser{
			Suspend: ce.Command != "unsuspend",
		})
		if err != nil {
			ce.Reply("Failed to %s: %v", ce.Command, err)
		} else {
			ce.React(SuccessReaction)
		}
	},
}

var cmdDeactivate = &CommandHandler{
	Name: "deactivate",
	Func: func(ce *CommandEvent) {
		if len(ce.Args) > 1 && ce.Args[1] != "--erase" {
			ce.Reply("Usage: `!deactivate <user ID> [--erase]`")
			return
		}
		err := ce.Meta.Bot.SynapseAdmin.DeactivateAccount(ce.Ctx, id.UserID(ce.Args[0]), synapseadmin.ReqDeleteUser{
			Erase: len(ce.Args) > 1 && ce.Args[1] == "--erase",
		})
		if err != nil {
			ce.Reply("Failed to deactivate: %v", err)
		} else {
			ce.React(SuccessReaction)
		}
	},
}

var cmdProtectRoom = &CommandHandler{
	Name:    "protect",
	Aliases: []string{"unprotect"},
	Func: func(ce *CommandEvent) {
		if len(ce.Args) < 1 {
			ce.Reply("Usage: `!rooms <protect/unprotect> <room ID or alias>...`")
			return
		}
		ce.Meta.protectedRoomsLock.RLock()
		evtContent := ce.Meta.protectedRoomsEvent
		if evtContent == nil {
			evtContent = &config.ProtectedRoomsEventContent{Rooms: []id.RoomID{}}
		}
		contentCopy := *evtContent
		contentCopy.Rooms = slices.Clone(contentCopy.Rooms)
		ce.Meta.protectedRoomsLock.RUnlock()
		changed := false
		for _, room := range ce.Args {
			roomID := resolveRoom(ce, room)
			if roomID == "" {
				continue
			}
			itemIdx := slices.Index(contentCopy.Rooms, roomID)
			if ce.Command == "protect" {
				if itemIdx >= 0 {
					ce.Reply("%s is already protected", format.SafeMarkdownCode(roomID))
					continue
				}
				contentCopy.Rooms = append(contentCopy.Rooms, roomID)
				changed = true
			} else {
				if itemIdx < 0 {
					ce.Reply("%s is not protected", format.SafeMarkdownCode(roomID))
					continue
				}
				contentCopy.Rooms = slices.Delete(contentCopy.Rooms, itemIdx, itemIdx+1)
				changed = true
			}
		}
		if changed {
			_, err := ce.Meta.Bot.SendStateEvent(ce.Ctx, ce.Meta.ManagementRoom, config.StateProtectedRooms, "", &contentCopy)
			if err != nil {
				ce.Reply("Failed to update protected rooms: %v", err)
				return
			}
			ce.React(SuccessReaction)
		}
	},
}

var cmdHelp = &CommandHandler{
	Name: "help",
	Func: func(ce *CommandEvent) {
		if len(ce.Args) == 0 {
			ce.Reply("Available commands:\n" +
				"* `!join <rooms...>` - Join a room\n" +
				"* `!knock <rooms...>` - Ask to join a room\n" +
				"* `!leave <rooms...>` - Leave a room\n" +
				"* `!powerlevel <room|all> <key> <level>` - Set a power level\n" +
				"* `!redact <event link or user ID> [reason]` - Redact all messages from a user\n" +
				"* `!redact-recent <room> <since duration> [reason]` - Redact all recent messages in a room\n" +
				"* `!kick <user ID> [reason]` - Kick a user from all rooms\n" +
				"* `!ban [--hash] <list shortcode> <entity> [reason]` - Add a ban policy\n" +
				"* `!takedown [--hash] <list shortcode> <entity>` - Add a takedown policy\n" +
				"* `!remove-ban <list shortcode> <entity>` - Remove a ban policy\n" +
				"* `!add-unban <list shortcode> <entity> [reason]` - Add a ban exclusion policy\n" +
				"* `!match <entity>` - Match an entity against all lists\n" +
				"* `!search <pattern>` - Search for rules by a pattern in all lists\n" +
				"* `!send-as-bot <room> <message>` - Send a message as the bot\n" +
				"* `![un]suspend <user ID>` - Suspend or unsuspend a user\n" +
				"* `!rooms <...>` - Manage rooms\n" +
				"* `!help <command>` - Show detailed help for a command\n" +
				"* `!help` - Show this help message\n" +
				"\n" +
				"All fields that want a room will accept both room IDs and aliases.\n",
			)
		} else {
			switch strings.ToLower(strings.TrimLeft(ce.Args[0], "!")) {
			case "rooms":
				ce.Reply(roomsHelp)
			default:
				ce.Reply("No help page for %s", format.SafeMarkdownCode(ce.Args[0]))
			}
		}
	},
}

func resolveRoomFull(ce *CommandEvent, room string) (roomID id.RoomID, roomAlias id.RoomAlias, via []string) {
	if strings.HasPrefix(room, "matrix:") || strings.HasPrefix(room, "https") {
		uri, err := id.ParseMatrixURIOrMatrixToURL(room)
		if err != nil {
			ce.Reply(err.Error())
			return
		}
		switch uri.Sigil1 {
		case '#':
			room = uri.RoomAlias().String()
		case '!':
			room = uri.RoomID().String()
			via = uri.Via
		default:
			ce.Reply("%s is not a room ID or alias", format.SafeMarkdownCode(uri.PrimaryIdentifier()))
			return
		}
	}

	if strings.HasPrefix(room, "#") {
		roomAlias = id.RoomAlias(room)
		resp, err := ce.Meta.Bot.ResolveAlias(ce.Ctx, roomAlias)
		if err != nil {
			ce.Log.Warn().Err(err).
				Str("room_input", room).
				Msg("Failed to resolve alias")
			ce.Reply("Failed to resolve alias %s: %v", format.SafeMarkdownCode(room), err)
			return
		}
		roomID = resp.RoomID
		via = resp.Servers[:min(5, len(resp.Servers))]
	} else {
		roomID = id.RoomID(room)
	}
	return
}

func resolveRoomIDOrAlias(ce *CommandEvent, room string) (string, []string) {
	roomID, roomAlias, via := resolveRoomFull(ce, room)
	if roomAlias != "" {
		return roomAlias.String(), nil
	}
	return roomID.String(), via
}

func resolveRoom(ce *CommandEvent, room string) id.RoomID {
	roomID, _, _ := resolveRoomFull(ce, room)
	return roomID
}

var homeserverPatternRegex = regexp.MustCompile(`^[a-zA-Z0-9.*?-]+\.[a-zA-Z0-9*?-]+$`)

func resolveEntity(ce *CommandEvent, entity string) (string, policylist.EntityType, bool) {
	if len(entity) == 0 {
		ce.Reply("No entity provided?")
		return "", "", false
	}
	if strings.HasPrefix(entity, "matrix:") || strings.HasPrefix(entity, "https") {
		uri, err := id.ParseMatrixURIOrMatrixToURL(entity)
		if err != nil {
			ce.Reply(err.Error())
			return "", "", false
		}
		switch uri.Sigil1 {
		case '!':
			entity = uri.RoomID().String()
		case '@':
			entity = uri.UserID().String()
		default:
			ce.Reply("%s is not a room or user ID", format.SafeMarkdownCode(uri.PrimaryIdentifier()))
			return "", "", false
		}
	}
	if entity[0] == '@' {
		return entity, policylist.EntityTypeUser, true
	} else if entity[0] == '!' {
		return entity, policylist.EntityTypeRoom, true
	} else if homeserverPatternRegex.MatchString(entity) {
		return entity, policylist.EntityTypeServer, true
	}
	ce.Reply("Invalid entity %s", format.SafeMarkdownCode(entity))
	return "", "", false
}

func (pe *PolicyEvaluator) SendPolicy(ctx context.Context, policyList id.RoomID, entityType policylist.EntityType, stateKey, rawEntity string, content *event.ModPolicyContent) (*mautrix.RespSendEvent, error) {
	if stateKey == "" {
		stateKeyHash := sha256.Sum256(append([]byte(rawEntity), []byte(content.Recommendation)...))
		stateKey = base64.StdEncoding.EncodeToString(stateKeyHash[:])
	}
	return pe.Bot.SendStateEvent(ctx, policyList, entityType.EventType(), stateKey, content)
}
