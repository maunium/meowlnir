package policyeval

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/glob"
	"go.mau.fi/util/progver"
	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/commands"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/event/cmdschema"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/synapseadmin"

	"go.mau.fi/meowlnir/config"
	"go.mau.fi/meowlnir/policylist"
	"go.mau.fi/meowlnir/util"
)

type CommandEvent = commands.Event[*PolicyEvaluator]
type CommandHandler = commands.Handler[*PolicyEvaluator]

type MjolnirShortcodeEventContent struct {
	Shortcode string `json:"shortcode"`
}

var StateMjolnirShortcode = event.Type{Type: "org.matrix.mjolnir.shortcode", Class: event.StateEventType}

const SuccessReaction = "✅"

func (pe *PolicyEvaluator) HandleCommand(ctx context.Context, evt *event.Event) {
	if !evt.Mautrix.WasEncrypted && pe.Bot.CryptoHelper != nil && pe.RequireEncryption {
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

type JoinArgs struct {
	Rooms []cmdschema.RoomIDOrString `json:"rooms"`
}

var cmdJoin = &CommandHandler{
	Name:        "join",
	Description: event.MakeExtensibleText("Join rooms by ID or alias. Doesn't do anything else than join."),
	Parameters: []*cmdschema.Parameter{{
		Key:    "rooms",
		Schema: cmdschema.Array(cmdschema.ParameterSchemaJoinableRoom),
	}},
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *JoinArgs) {
		for _, arg := range args.Rooms {
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
	}),
}

var cmdKnock = &CommandHandler{
	Name:        "knock",
	Description: event.MakeExtensibleText("Request to join a knockable room by ID or alias"),
	Parameters: []*cmdschema.Parameter{{
		Key:    "rooms",
		Schema: cmdschema.Array(cmdschema.ParameterSchemaJoinableRoom),
	}},
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *JoinArgs) {
		for _, arg := range args.Rooms {
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
	}),
}

var cmdLeave = &CommandHandler{
	Name:        "leave",
	Description: event.MakeExtensibleText("Leave a room by ID or alias"),
	Parameters: []*cmdschema.Parameter{{
		Key:    "rooms",
		Schema: cmdschema.Array(cmdschema.ParameterSchemaJoinableRoom),
	}},
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *JoinArgs) {
		if len(args.Rooms) == 0 {
			ce.Reply("Usage: `!leave <room ID>...`")
			return
		}
		for _, arg := range args.Rooms {
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
	}),
}

type PowerLevelArgs struct {
	Room  cmdschema.RoomIDOrString `json:"room"`
	Key   string                   `json:"key"`
	Level int                      `json:"level"`
}

var cmdPowerLevel = &CommandHandler{
	Name:        "powerlevel",
	Aliases:     []string{"pl"},
	Description: event.MakeExtensibleText("Adjust power levels in protected rooms"),
	Parameters: []*cmdschema.Parameter{{
		Key: "room",
		Schema: cmdschema.Union(
			cmdschema.Literal("all"),
			cmdschema.PrimitiveTypeRoomID.Schema(),
		),
	}, {
		Key: "key",
		Schema: cmdschema.Union(
			cmdschema.Literal("invite"),
			cmdschema.Literal("kick"),
			cmdschema.Literal("ban"),
			cmdschema.Literal("redact"),
			cmdschema.Literal("users_default"),
			cmdschema.Literal("state_default"),
			cmdschema.Literal("events_default"),
			cmdschema.Literal("notifications.room"),
			cmdschema.PrimitiveTypeUserID.Schema(),
			cmdschema.PrimitiveTypeString.Schema(),
		),
	}, {
		Key:    "level",
		Schema: cmdschema.PrimitiveTypeInteger.Schema(),
	}},
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *PowerLevelArgs) {
		var rooms []id.RoomID
		if args.Room == "all" {
			rooms = ce.Meta.GetProtectedRooms()
		} else {
			room := resolveRoom(ce, args.Room)
			if room == "" {
				return
			}
			rooms = []id.RoomID{room}
		}
		level := args.Level
		for _, room := range rooms {
			var pls event.PowerLevelsEventContent
			// No need to fetch the create event here, this is a manual update that is allowed to fail if the user holds it wrong
			err := ce.Meta.Bot.Client.StateEvent(ce.Ctx, room, event.StatePowerLevels, "", &pls)
			if err != nil {
				ce.Reply("Failed to get power levels in %s: %v", format.SafeMarkdownCode(room), err)
				return
			}
			const MagicUnsetValue = -1644163703
			var oldLevel int
			switch strings.ToLower(args.Key) {
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
				if strings.HasPrefix(args.Key, "@") {
					oldLevel = pls.GetUserLevel(id.UserID(args.Key))
					pls.SetUserLevel(id.UserID(args.Key), level)
				} else if strings.ContainsRune(args.Key, '.') {
					if pls.Events == nil {
						pls.Events = make(map[string]int)
					}
					var ok bool
					oldLevel, ok = pls.Events[args.Key]
					if !ok {
						oldLevel = MagicUnsetValue
					}
					pls.Events[args.Key] = level
				} else {
					ce.Reply("Invalid power level key %s", format.SafeMarkdownCode(args.Key))
					return
				}
			}
			if oldLevel == level && oldLevel != MagicUnsetValue {
				ce.Reply(
					"Power level for %s in %s is already set to %s",
					format.SafeMarkdownCode(args.Key),
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
	}),
}

type RedactArgs struct {
	Target cmdschema.RoomIDOrString `json:"target"`
	Reason string                   `json:"reason"`
}

var cmdRedact = &CommandHandler{
	Name:        "redact",
	Description: event.MakeExtensibleText("Redact all events of a user or a specific event"),
	Parameters: []*cmdschema.Parameter{{
		Key: "target",
		Schema: cmdschema.Union(
			cmdschema.PrimitiveTypeUserID.Schema(),
			cmdschema.PrimitiveTypeEventID.Schema(),
		),
	}, {
		Key:      "reason",
		Schema:   cmdschema.PrimitiveTypeString.Schema(),
		Optional: true,
	}},
	TailParam: "reason",
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *RedactArgs) {
		var target *id.MatrixURI
		var err error
		if args.Target[0] == '@' {
			target = &id.MatrixURI{
				Sigil1: '@',
				MXID1:  string(args.Target[1:]),
			}
		} else {
			target, err = id.ParseMatrixURIOrMatrixToURL(string(args.Target))
			if err != nil {
				ce.Reply("Failed to parse %s: %v", format.SafeMarkdownCode(args.Target), err)
				return
			}
		}
		if target.Sigil1 == '@' {
			ce.Meta.RedactUser(ce.Ctx, target.UserID(), args.Reason, false)
		} else if target.Sigil1 == '!' && target.Sigil2 == '$' {
			_, err = ce.Meta.Bot.RedactEvent(ce.Ctx, target.RoomID(), target.EventID(), mautrix.ReqRedact{Reason: args.Reason})
			if err != nil {
				ce.Reply("Failed to redact event %s: %v", format.SafeMarkdownCode(target.EventID()), err)
				return
			}
		} else {
			ce.Reply("Invalid target %s (must be a user ID or event link)", format.SafeMarkdownCode(args.Target))
			return
		}
		ce.React(SuccessReaction)
	}),
}

type RedactRecentParams struct {
	Target cmdschema.RoomIDOrString `json:"target"`
	Since  string                   `json:"since"`
	Reason string                   `json:"reason"`
}

var cmdRedactRecent = &CommandHandler{
	Name:        "redact-recent",
	Description: event.MakeExtensibleText("Redact recent events in a room"),
	Parameters: []*cmdschema.Parameter{{
		Key:    "target",
		Schema: cmdschema.ParameterSchemaJoinableRoom,
	}, {
		Key:    "since",
		Schema: cmdschema.PrimitiveTypeString.Schema(),
	}, {
		Key:      "reason",
		Schema:   cmdschema.PrimitiveTypeString.Schema(),
		Optional: true,
	}},
	TailParam: "reason",
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *RedactRecentParams) {
		room := resolveRoom(ce, args.Target)
		if room == "" {
			return
		}
		since, err := time.ParseDuration(args.Since)
		if err != nil {
			ce.Reply("Invalid duration %s: %v", format.SafeMarkdownCode(args.Since), err)
			return
		}
		redactedCount, err := ce.Meta.redactRecentMessages(ce.Ctx, room, "", since, false, args.Reason)
		if err != nil {
			ce.Reply("Failed to redact recent messages: %v", err)
			return
		}
		ce.Reply("Redacted %d messages", redactedCount)
		ce.React(SuccessReaction)
	}),
}

type KickParams struct {
	Target string                   `json:"target"`
	Reason string                   `json:"reason"`
	Force  bool                     `json:"force"`
	Room   cmdschema.RoomIDOrString `json:"room"`
}

var cmdKick = &CommandHandler{
	Name:        "kick",
	Description: event.MakeExtensibleText("Kick users from rooms"),
	Parameters: []*cmdschema.Parameter{{
		Key: "target",
		Schema: cmdschema.Union(
			cmdschema.PrimitiveTypeUserID.Schema(),
			cmdschema.PrimitiveTypeString.Schema(),
		),
	}, {
		Key:      "reason",
		Schema:   cmdschema.PrimitiveTypeString.Schema(),
		Optional: true,
	}, {
		Key:      "force",
		Schema:   cmdschema.PrimitiveTypeBoolean.Schema(),
		Optional: true,
	}, {
		Key:      "room",
		Schema:   cmdschema.ParameterSchemaJoinableRoom,
		Optional: true,
	}},
	TailParam: "reason",
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *KickParams) {
		var targetRoom id.RoomID
		if args.Room != "" {
			targetRoom = resolveRoom(ce, args.Room)
			if targetRoom == "" {
				return
			}
		}
		pattern := glob.Compile(args.Target)
		users := slices.Collect(ce.Meta.findMatchingUsers(pattern, nil, true))
		if len(users) > 10 && !args.Force {
			// TODO replace the force flag with a reaction confirmation
			ce.Reply("%d users matching %s found, use `--force` to kick all of them.", len(users), format.SafeMarkdownCode(args.Target))
			return
		}
		for _, userID := range users {
			successCount := 0
			var rooms []id.RoomID
			if targetRoom == "" {
				rooms = ce.Meta.getRoomsUserIsIn(userID)
				if len(rooms) == 0 {
					continue
				}
			} else {
				rooms = []id.RoomID{targetRoom}
			}
			roomStrings := make([]string, len(rooms))
			for i, room := range rooms {
				roomStrings[i] = format.MarkdownMentionRoomID("", room)
				var err error
				if !ce.Meta.DryRun {
					_, err = ce.Meta.Bot.KickUser(ce.Ctx, room, &mautrix.ReqKickUser{
						Reason: args.Reason,
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
			ce.Reply("No users matching %s found in any rooms", format.SafeMarkdownCode(args.Target))
			return
		}
		ce.React(SuccessReaction)
	}),
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
				"%s already has a %s recommendation in %s for %s (sent by %s at %s)",
				format.SafeMarkdownCode(policy.EntityOrHash()),
				format.SafeMarkdownCode(rec.Recommendation),
				format.MarkdownMentionRoomID(list.Name, list.RoomID, ce.Meta.Bot.ServerName),
				format.SafeMarkdownCode(rec.Reason),
				format.MarkdownMention(rec.Sender),
				time.UnixMilli(rec.Timestamp).String(),
			)
			return "", false
		} else {
			return rec.StateKey, true
		}
	} else if (policy.Recommendation != event.PolicyRecommendationUnban && rec.Recommendation == event.PolicyRecommendationUnban) ||
		(policy.Recommendation == event.PolicyRecommendationUnban && rec.Recommendation != event.PolicyRecommendationUnban) {
		ce.Reply(
			"%s has a conflicting %s recommendation for %s (sent by %s at %s)",
			format.SafeMarkdownCode(policy.EntityOrHash()),
			format.SafeMarkdownCode(rec.Recommendation),
			format.SafeMarkdownCode(rec.Reason),
			format.MarkdownMention(rec.Sender),
			time.UnixMilli(rec.Timestamp).String(),
		)
		return "", false
	} else {
		return "", true
	}
}

type BanParams struct {
	List   string `json:"list"`
	Entity string `json:"entity"`
	Reason string `json:"reason"`
	Hash   bool   `json:"hash"`
}

var cmdTakedown = &CommandHandler{
	Name:        "takedown",
	Description: event.MakeExtensibleText("Send a takedown policy to a policy list"),
}
var cmdBan = &CommandHandler{
	Name:        "ban",
	Description: event.MakeExtensibleText("Send a ban policy to a policy list"),
	Parameters: []*cmdschema.Parameter{{
		Key:    "list",
		Schema: cmdschema.PrimitiveTypeString.Schema(),
	}, {
		Key: "entity",
		Schema: cmdschema.Union(
			cmdschema.PrimitiveTypeUserID.Schema(),
			cmdschema.PrimitiveTypeServerName.Schema(),
			cmdschema.PrimitiveTypeString.Schema(),
		),
	}, {
		Key:      "reason",
		Schema:   cmdschema.PrimitiveTypeString.Schema(),
		Optional: true,
	}, {
		Key:      "hash",
		Schema:   cmdschema.PrimitiveTypeBoolean.Schema(),
		Optional: true,
	}},
	TailParam: "reason",
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *BanParams) {
		list := ce.Meta.FindListByShortcode(args.List)
		if list == nil {
			ce.Reply("List %s not found", format.SafeMarkdownCode(args.List))
			return
		}
		entity, entityType, ok := resolveEntity(ce, args.Entity)
		if !ok {
			return
		}
		policy := &event.ModPolicyContent{
			Entity:         entity,
			Reason:         args.Reason,
			Recommendation: event.PolicyRecommendationBan,
		}
		if args.Hash {
			targetHash := util.SHA256String(policy.Entity)
			policy.UnstableHashes = &event.PolicyHashes{
				SHA256: base64.StdEncoding.EncodeToString(targetHash[:]),
			}
		}
		if ce.Handler == cmdTakedown {
			policy.Recommendation = event.PolicyRecommendationUnstableTakedown
		}
		existingStateKey, ok := ce.Meta.deduplicatePolicy(ce, list, policy, entityType)
		if !ok {
			return
		}
		target := policy.Entity
		if args.Hash {
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
	}),
}

var cmdRemoveBan = &CommandHandler{
	Name:        "remove-ban",
	Description: event.MakeExtensibleText("Remove a ban policy from a policy list"),
}
var cmdRemoveUnban = &CommandHandler{
	Name:        "remove-unban",
	Description: event.MakeExtensibleText("Remove an unban policy from a policy list"),
}
var cmdRemovePolicy = &CommandHandler{
	Name:        "remove-policy",
	Description: event.MakeExtensibleText("Remove a policy from a policy list"),
	Parameters:  cmdBan.Parameters[:2],
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *BanParams) {
		list := ce.Meta.FindListByShortcode(args.List)
		if list == nil {
			ce.Reply("List %s not found", format.SafeMarkdownCode(args.List))
			return
		}
		target, entityType, ok := resolveEntity(ce, args.Entity)
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
			ce.Reply("No rule banning %s found in %s", format.SafeMarkdownCode(target), format.MarkdownMentionRoomID(list.Name, list.RoomID))
			return
		}
		if rec := match.Recommendations().BanOrUnban; rec != nil {
			existingStateKey = rec.StateKey
			// TODO: handle wildcards and multiple matches, etc
			if ce.Handler == cmdRemoveUnban && rec.Recommendation != event.PolicyRecommendationUnban {
				ce.Reply("%s does not have an unban recommendation", format.SafeMarkdownCode(target))
				return
			} else if ce.Handler == cmdRemoveBan && rec.Recommendation != event.PolicyRecommendationBan {
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
	}),
}

var cmdAddUnban = &CommandHandler{
	Name:        "add-unban",
	Description: event.MakeExtensibleText("Add an unban policy to a policy list"),
	Parameters:  cmdBan.Parameters[:3],
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *BanParams) {
		list := ce.Meta.FindListByShortcode(args.List)
		if list == nil {
			ce.Reply("List %s not found", format.SafeMarkdownCode(args.List))
			return
		}
		entity, entityType, ok := resolveEntity(ce, args.Entity)
		if !ok {
			return
		}
		policy := &event.ModPolicyContent{
			Entity:         entity,
			Reason:         args.Reason,
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
	}),
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
		match = ce.Meta.Store.MatchUser(ce.Meta.GetWatchedListsForMatch(), id.UserID(target))
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
				formattedRooms[i] = fmt.Sprintf("* %s", format.MarkdownMentionRoomID(name, roomID))
			}
			ce.Meta.protectedRoomsLock.RUnlock()
			ce.Reply("User is in %d protected rooms:\n\n%s", len(rooms), strings.Join(formattedRooms, "\n"))
		}
	} else if entityType == policylist.EntityTypeRoom {
		start := time.Now()
		match = ce.Meta.Store.MatchRoom(ce.Meta.GetWatchedListsForMatch(), id.RoomID(target))
		dur = time.Since(start)
	} else if entityType == policylist.EntityTypeServer {
		start := time.Now()
		match = ce.Meta.Store.MatchServer(ce.Meta.GetWatchedListsForMatch(), target)
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
				"* [%s] %s set recommendation %s for %s at %s for %s",
				format.EscapeMarkdown(policyRoomName),
				format.MarkdownMention(policy.Sender),
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

type MatchParams struct {
	Entities []string `json:"entity"`
}

var cmdMatch = &CommandHandler{
	Name:        "match",
	Description: event.MakeExtensibleText("Search for policies which the given entity would match"),
	Parameters: []*cmdschema.Parameter{{
		Key: "entity",
		Schema: cmdschema.Array(cmdschema.Union(
			cmdschema.PrimitiveTypeUserID.Schema(),
			cmdschema.PrimitiveTypeServerName.Schema(),
			cmdschema.PrimitiveTypeString.Schema(),
		)),
	}},
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *MatchParams) {
		for _, arg := range args.Entities {
			doMatch(ce, arg)
		}
	}),
}

type SearchParams struct {
	Pattern string `json:"pattern"`
}

var cmdSearch = &CommandHandler{
	Name:        "search",
	Description: event.MakeExtensibleText("Search for policies whose target entity matches a given glob pattern"),
	Parameters: []*cmdschema.Parameter{{
		Key:    "pattern",
		Schema: cmdschema.PrimitiveTypeString.Schema(),
	}},
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *SearchParams) {
		target := args.Pattern
		start := time.Now()
		match := ce.Meta.Store.Search(ce.Meta.GetWatchedListsForMatch(), target)
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
					"* [%s] %s set recommendation %s for %ss matching %s at %s for %s",
					format.EscapeMarkdown(policyRoomName),
					format.MarkdownMention(policy.Sender),
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
					userStrings[i] = fmt.Sprintf("* %s", format.MarkdownMention(user))
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
	}),
}

type SendAsBotParams struct {
	Room    cmdschema.RoomIDOrString `json:"room"`
	Message string                   `json:"message"`
}

var cmdSendAsBot = &CommandHandler{
	Name:        "send-as-bot",
	Description: event.MakeExtensibleText("Send a message to a room as the bot user"),
	Parameters: []*cmdschema.Parameter{{
		Key:    "room",
		Schema: cmdschema.ParameterSchemaJoinableRoom,
	}, {
		Key:    "message",
		Schema: cmdschema.PrimitiveTypeString.Schema(),
	}},
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *SendAsBotParams) {
		target := resolveRoom(ce, args.Room)
		if target == "" {
			return
		}
		if ce.Meta.Untrusted && !ce.Meta.IsProtectedRoom(target) {
			ce.Reply("Can't send messages to unprotected rooms")
			return
		}
		resp, err := ce.Meta.Bot.SendMessageEvent(ce.Ctx, target, event.EventMessage, &event.MessageEventContent{
			MsgType: event.MsgText,
			Body:    args.Message,
		})
		if err != nil {
			ce.Reply("Failed to send message to %s: %v", format.MarkdownMentionRoomID("", target), err)
		} else {
			ce.Reply("Sent message to %s: [%s](%s)", format.MarkdownMentionRoomID("", target), resp.EventID, target.EventURI(resp.EventID).MatrixToURL())
		}
	}),
}

const roomsHelp = "Available `!rooms` subcommands:\n\n" +
	"* `!rooms list` - List all protected rooms\n" +
	"* `!rooms info <room ID or alias>` - Get information about a room using the Synapse admin API\n" +
	"* `!rooms delete [--async] <room ID>` - Purge a room from the server\n" +
	"* `!rooms block [--async] <room ID>` - Purge and block a room from the server\n" +
	"* `!rooms delete-status <delete ID>` - Get the status of a room deletion (if `--async` was used)\n" +
	"* `!rooms protect <room ID or alias>...` - Start protecting a room.\n" +
	"* `!rooms unprotect <room ID or alias>...` - Stop protecting a room.\n"
const listsHelp = "Available `!lists` subcommands:\n\n" +
	"* `!lists create <shortcode> [--alias=localpart] [--name=room name] [--public]` - Create a new policy list\n" +
	"* `!lists subscribe <room ID or alias> [shortcode] [--dont-apply] [--dont-apply-acls] [--disable-notifications] " +
	"[--dont-auto-unban] [--auto-suspend]` - Subscribe a room to a policy list\n" +
	"* `!lists unsubscribe <room ID, alias, or shortcode>` - Unsubscribe a room from a policy list\n"

var cmdRooms = &CommandHandler{
	Name:        "rooms",
	Aliases:     []string{"room"},
	Description: event.MakeExtensibleText("Manage various things related to rooms"),
	Parameters:  []*cmdschema.Parameter{},
	Subcommands: []*CommandHandler{
		cmdListProtectedRooms,
		cmdProtectRoom,
		cmdUnprotectRoom,
		cmdRoomInfo,
		cmdRoomDelete,
		cmdRoomBlock,
		cmdRoomDeleteStatus,
		commands.MakeUnknownCommandHandler[*PolicyEvaluator]("!"),
	},
	Func: func(ce *commands.Event[*PolicyEvaluator]) {
		ce.Reply(roomsHelp)
	},
}

var cmdListProtectedRooms = &CommandHandler{
	Name:        "list",
	Description: event.MakeExtensibleText("View the list of rooms protected by this bot"),
	Parameters:  []*cmdschema.Parameter{},
	Func: func(ce *CommandEvent) {
		var buf strings.Builder
		buf.WriteString("Protected rooms:\n\n")
		ce.Meta.protectedRoomsLock.RLock()
		for roomID, meta := range ce.Meta.protectedRooms {
			_, _ = fmt.Fprintf(&buf, "* %s (%s)\n", format.MarkdownMentionRoomID(meta.Name, roomID, ce.Meta.Bot.ServerName), format.SafeMarkdownCode(roomID))
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

type RoomInfoParams struct {
	Room cmdschema.RoomIDOrString `json:"room"`
}

var cmdRoomInfo = &CommandHandler{
	Name:        "info",
	Description: event.MakeExtensibleText("View the info of a room using the Synapse admin API"),
	Parameters: []*cmdschema.Parameter{{
		Key:    "room",
		Schema: cmdschema.ParameterSchemaJoinableRoom,
	}},
	Func: commands.WithParsedArgs(func(ce *commands.Event[*PolicyEvaluator], args *RoomInfoParams) {
		roomID := resolveRoom(ce, args.Room)
		if roomID == "" {
			return
		}
		roomInfo, err := ce.Meta.Bot.SynapseAdmin.RoomInfo(ce.Ctx, roomID)
		if err != nil {
			ce.Reply("Failed to get room info: %v", err)
			return
		}
		ce.Reply(formatRoomInfo(roomInfo))
	}),
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

type RoomDeleteStatusParams struct {
	DeleteID string `json:"delete_id"`
}

var cmdRoomDeleteStatus = &CommandHandler{
	Name:        "delete-status",
	Description: event.MakeExtensibleText("Check the status of an async room deletion"),
	Parameters: []*cmdschema.Parameter{{
		Key:    "delete_id",
		Schema: cmdschema.PrimitiveTypeString.Schema(),
	}},
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *RoomDeleteStatusParams) {
		resp, err := ce.Meta.Bot.SynapseAdmin.DeleteRoomStatus(ce.Ctx, args.DeleteID)
		if err != nil {
			ce.Reply("Failed to get delete status for %s: %v", format.SafeMarkdownCode(args.DeleteID), err)
		} else if resp.Status == "complete" {
			ce.Reply("Deletion is complete:\n\n%s", formatDeleteResult(resp.ShutdownRoom))
		} else if resp.Status == "failed" {
			ce.Reply("Deletion failed: %s", resp.Error)
		} else {
			ce.Reply("Deletion is still in progress (%s)", resp.Status)
		}
	}),
}

type RoomDeleteParams struct {
	RoomID  cmdschema.RoomIDValue `json:"room_id"`
	Force   bool                  `json:"force"`
	Async   bool                  `json:"async"`
	Confirm bool                  `json:"confirm"`
}

var cmdRoomBlock = &CommandHandler{
	Name:        "block",
	Description: event.MakeExtensibleText("Delete and block a room using the Synapse admin API"),
}

var cmdRoomDelete = &CommandHandler{
	Name:        "delete",
	Aliases:     []string{"purge"},
	Description: event.MakeExtensibleText("Delete a room using the Synapse admin API"),
	Parameters: []*cmdschema.Parameter{{
		Key:    "room_id",
		Schema: cmdschema.PrimitiveTypeRoomID.Schema(),
	}, {
		Key:      "async",
		Schema:   cmdschema.PrimitiveTypeBoolean.Schema(),
		Optional: true,
	}, {
		Key:      "confirm",
		Schema:   cmdschema.PrimitiveTypeBoolean.Schema(),
		Optional: true,
	}, {
		Key:      "force",
		Schema:   cmdschema.PrimitiveTypeBoolean.Schema(),
		Optional: true,
	}},
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *RoomDeleteParams) {
		roomID := args.RoomID.RoomID
		if args.Confirm {
			andBlock := ""
			if ce.Handler == cmdRoomBlock {
				andBlock = " and block"
			}
			evtID := ce.Respond(fmt.Sprintf("Really purge%s %s?", andBlock, format.SafeMarkdownCode(roomID)), commands.ReplyOpts{
				Reply:         true,
				AllowMarkdown: true,
				Extra: map[string]any{
					commands.ReactionCommandsKey: map[string]any{
						"/confirm": event.MSC4391BotCommandInputCustom[*RoomDeleteParams]{
							Command: fmt.Sprintf("rooms %s", ce.Command),
							Arguments: &RoomDeleteParams{
								RoomID:  args.RoomID,
								Force:   args.Force,
								Async:   args.Async,
								Confirm: false,
							},
						},
						"/cancel": "",
					},
				},
			})
			ce.Meta.sendReactions(ce.Ctx, evtID, "/cancel", "/confirm")
			return
		}
		req := synapseadmin.ReqDeleteRoom{
			Purge:      true,
			ForcePurge: args.Force,
			Block:      ce.Handler == cmdRoomBlock,
		}
		if ce.Meta.DryRun {
			ce.Reply("Would have deleted room %s if dry run wasn't enabled", format.SafeMarkdownCode(roomID))
			return
		}
		if args.Async {
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
	}),
}

type SuspendParams struct {
	UserID id.UserID `json:"user"`
}

var cmdUnsuspend = &CommandHandler{
	Name:        "unsuspend",
	Description: event.MakeExtensibleText("Unsuspend a local account"),
}
var cmdSuspend = &CommandHandler{
	Name:        "suspend",
	Description: event.MakeExtensibleText("Suspend a local account"),
	Parameters: []*cmdschema.Parameter{{
		Key:    "user",
		Schema: cmdschema.PrimitiveTypeUserID.Schema(),
	}},
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *SuspendParams) {
		err := ce.Meta.setSuspendedStatus(ce.Ctx, args.UserID, ce.Handler != cmdUnsuspend)
		if err != nil {
			ce.Reply("Failed to %s: %v", ce.Command, err)
		} else {
			ce.React(SuccessReaction)
		}
	}),
}

type DeactivateParams struct {
	UserID id.UserID `json:"user"`
	Erase  bool      `json:"erase"`
}

var cmdDeactivate = &CommandHandler{
	Name:        "deactivate",
	Description: event.MakeExtensibleText("Permanently deactivate a local account"),
	Parameters: []*cmdschema.Parameter{{
		Key:    "user",
		Schema: cmdschema.PrimitiveTypeUserID.Schema(),
	}, {
		Key:      "erase",
		Schema:   cmdschema.PrimitiveTypeBoolean.Schema(),
		Optional: true,
	}},
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *DeactivateParams) {
		err := ce.Meta.Bot.SynapseAdmin.DeactivateAccount(ce.Ctx, args.UserID, synapseadmin.ReqDeleteUser{
			Erase: args.Erase,
		})
		if err != nil {
			ce.Reply("Failed to deactivate: %v", err)
		} else {
			ce.React(SuccessReaction)
		}
	}),
}

type BotProfileParams struct {
	Field string `json:"field"`
	Value string `json:"value"`
}

var cmdBotProfile = &CommandHandler{
	Name:        "bot-profile",
	Aliases:     []string{"profile"},
	Description: event.MakeExtensibleText("Change the profile of the bot"),
	Parameters: []*cmdschema.Parameter{{
		Key:    "field",
		Schema: cmdschema.Enum("displayname", "name", "avatar", "avatar_url"),
	}, {
		Key:    "value",
		Schema: cmdschema.PrimitiveTypeString.Schema(),
	}},
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *BotProfileParams) {
		switch strings.ToLower(args.Field) {
		case "displayname", "name":
			err := ce.Meta.Bot.Intent.SetDisplayName(ce.Ctx, args.Value)
			if err != nil {
				ce.Log.Err(err).Msg("Failed to update bot displayname")
				ce.Reply("Failed to update displayname")
				return
			}
			ce.Meta.Bot.Meta.Displayname = args.Value
		case "avatar", "avatar_url", "avatar-url":
			parsed, err := id.ParseContentURI(args.Value)
			if err != nil {
				ce.Reply("Malformed avatar URL %s: %v", format.SafeMarkdownCode(args.Value), err)
				return
			}
			err = ce.Meta.Bot.Intent.SetAvatarURL(ce.Ctx, parsed)
			if err != nil {
				ce.Log.Err(err).Msg("Failed to update bot avatar")
				ce.Reply("Failed to update avatar")
				return
			}
			ce.Meta.Bot.Meta.AvatarURL = parsed
		default:
			ce.Reply("Usage: `!bot-profile <displayname|avatar> <new value>`")
			return
		}
		err := ce.Meta.DB.Bot.Put(ce.Ctx, ce.Meta.Bot.Meta)
		if err != nil {
			ce.Log.Err(err).Msg("Failed to save bot profile to database")
		}
	}),
}

type ProvisionParams struct {
	UserID id.UserID `json:"user"`
	Force  bool      `json:"force"`
}

var cmdProvision = &CommandHandler{
	Name:        "provision",
	Description: event.MakeExtensibleText("Provision a new Meowlnir4All bot for the given user"),
	Parameters: []*cmdschema.Parameter{{
		Key:    "user",
		Schema: cmdschema.PrimitiveTypeUserID.Schema(),
	}, {
		Key:      "force",
		Schema:   cmdschema.PrimitiveTypeBoolean.Schema(),
		Optional: true,
	}},
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *ProvisionParams) {
		if ce.Meta.provisionM4A == nil {
			ce.Reply("This is not the Meowlnir4All admin room")
			return
		}
		var ownerName string
		if !args.Force {
			profile, err := ce.Meta.Bot.GetProfile(ce.Ctx, args.UserID)
			if err != nil || profile == nil || profile.DisplayName == "" {
				ce.Reply("Profile not found for %s, are you sure the user ID is correct?", format.SafeMarkdownCode(args.UserID))
				return
			}
			if profile != nil {
				ownerName = profile.DisplayName
			}
		}
		if ownerName == "" {
			ownerName = args.UserID.String()
		}
		userID, roomID, err := ce.Meta.provisionM4A(ce.Ctx, args.UserID)
		if err != nil {
			ce.Log.Err(err).Msg("Failed to provision new M4A bot")
			ce.Reply("Failed to provision bot: %v", err)
			return
		}
		ce.Reply(
			"Successfully provisioned %s for %s with management room %s",
			format.MarkdownMention(userID),
			format.MarkdownMentionWithName(ownerName, args.UserID),
			format.MarkdownMentionRoomID("", roomID, ce.Meta.Bot.ServerName),
		)
	}),
}

type ProtectRoomParams struct {
	Rooms []cmdschema.RoomIDOrString `json:"room"`
}

var cmdUnprotectRoom = &CommandHandler{
	Name:        "unprotect",
	Description: event.MakeExtensibleText("Remove a room from the protected rooms list"),
}

var cmdProtectRoom = &CommandHandler{
	Name:        "protect",
	Description: event.MakeExtensibleText("Add rooms to the protected rooms list"),
	Parameters: []*cmdschema.Parameter{{
		Key:    "room",
		Schema: cmdschema.Array(cmdschema.ParameterSchemaJoinableRoom),
	}},
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *ProtectRoomParams) {
		ce.Meta.protectedRoomsLock.RLock()
		evtContent := ce.Meta.protectedRoomsEvent
		if evtContent == nil {
			evtContent = &config.ProtectedRoomsEventContent{Rooms: []id.RoomID{}}
		}
		contentCopy := *evtContent
		contentCopy.Rooms = slices.Clone(contentCopy.Rooms)
		ce.Meta.protectedRoomsLock.RUnlock()
		changed := false
		for _, room := range args.Rooms {
			roomID := resolveRoom(ce, room)
			if roomID == "" {
				continue
			}
			itemIdx := slices.Index(contentCopy.Rooms, roomID)
			if ce.Handler != cmdUnprotectRoom {
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
	}),
}

var VersionInfo progver.ProgramVersion

var cmdVersion = &CommandHandler{
	Name:        "version",
	Description: event.MakeExtensibleText("View the running Meowlnir version"),
	Parameters:  []*cmdschema.Parameter{},
	Func: func(ce *CommandEvent) {
		ce.Reply(VersionInfo.MarkdownDescription())
	},
}

type ListsSubscribeParams struct {
	Room                 cmdschema.RoomIDOrString `json:"room"`
	Shortcode            string                   `json:"shortcode"`
	DontApply            bool                     `json:"dont-apply"`
	DontApplyAcls        bool                     `json:"dont-apply-acls"`
	DisableNotifications bool                     `json:"disable-notifications"`
	DontAutoUnban        bool                     `json:"dont-auto-unban"`
	AutoSuspend          bool                     `json:"auto-suspend"`
}

var cmdListsSubscribe = &CommandHandler{
	Name:    "subscribe",
	Aliases: []string{"watch"},
	Parameters: []*cmdschema.Parameter{
		{
			Key:    "room",
			Schema: cmdschema.ParameterSchemaJoinableRoom,
		},
		{
			Key:      "shortcode",
			Schema:   cmdschema.PrimitiveTypeString.Schema(),
			Optional: true,
		},
		{
			Key:      "dont-apply",
			Schema:   cmdschema.PrimitiveTypeBoolean.Schema(),
			Optional: true,
		},
		{
			Key:      "dont-apply-acls",
			Schema:   cmdschema.PrimitiveTypeBoolean.Schema(),
			Optional: true,
		},
		{
			Key:      "disable-notifications",
			Schema:   cmdschema.PrimitiveTypeBoolean.Schema(),
			Optional: true,
		},
		{
			Key:      "dont-auto-unban",
			Schema:   cmdschema.PrimitiveTypeBoolean.Schema(),
			Optional: true,
		},
		{
			Key:      "auto-suspend",
			Schema:   cmdschema.PrimitiveTypeBoolean.Schema(),
			Optional: true,
		},
	},
	TailParam:   "shortcode",
	Description: event.MakeExtensibleText("Subscribe to a policy list"),
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *ListsSubscribeParams) {
		if args.Room == "" {
			ce.Reply(
				"Usage: `!lists subscribe <room ID or alias> [shortcode] [--dont-apply] [--dont-apply-acls] " +
					"[--disable-notifications] [--dont-auto-unban] [--auto-suspend]`",
			)
			return
		}
		ce.Meta.watchedListsLock.RLock()
		evtContent := ce.Meta.watchedListsEvent
		if evtContent == nil {
			evtContent = &config.WatchedListsEventContent{Lists: []config.WatchedPolicyList{}}
		}
		contentCopy := *evtContent
		contentCopy.Lists = slices.Clone(contentCopy.Lists)
		ce.Meta.watchedListsLock.RUnlock()
		resolvedRoom, _, via := resolveRoomFull(ce, string(args.Room))
		if resolvedRoom == "" {
			ce.Reply("Failed to resolve room %s", format.SafeMarkdownCode(args.Room))
			return
		}
		_, err := ce.Meta.Bot.JoinRoom(ce.Ctx, resolvedRoom.String(), &mautrix.ReqJoinRoom{Via: via})
		if err != nil {
			ce.Reply("Failed to join room %s: %v", format.SafeMarkdownCode(resolvedRoom), err)
			return
		}

		resolvedName, _ := ce.Meta.resolveRoomName(ce.Ctx, resolvedRoom)
		resolvedNameMD := format.MarkdownMentionRoomID(resolvedName, resolvedRoom, ce.Meta.Bot.ServerName)

		if args.Shortcode == "" {
			var scEvtContent MjolnirShortcodeEventContent
			if err := ce.Meta.Bot.StateEvent(ce.Ctx, resolvedRoom, StateMjolnirShortcode, "", &scEvtContent); err != nil {
				if !errors.Is(err, mautrix.MNotFound) {
					ce.Reply("Failed to get shortcode for %s: %v", resolvedNameMD, err)
					return
				}
			}
			if scEvtContent.Shortcode == "" {
				ce.Reply("No room-provided shortcode found for %s, please manually specify one.", resolvedNameMD)
				return
			}
			args.Shortcode = scEvtContent.Shortcode
		}

		for _, list := range contentCopy.Lists {
			if list.RoomID == resolvedRoom {
				ce.Reply("Already subscribed to %s", resolvedNameMD)
				return
			}
			if list.Shortcode == args.Shortcode {
				ce.Reply("Shortcode %s is already in use for %s", format.SafeMarkdownCode(args.Shortcode), resolvedNameMD)
				return
			}
		}

		if resolvedName == "" {
			// the shortcode is a sensible placeholder name
			resolvedName = args.Shortcode
		}
		if strings.Contains(args.Shortcode, " ") {
			ce.Reply("Shortcode cannot contain spaces")
			return
		}
		newList := config.WatchedPolicyList{
			RoomID:             resolvedRoom,
			Shortcode:          args.Shortcode,
			Name:               resolvedName,
			DontApply:          args.DontApply,
			DontApplyACL:       args.DontApplyAcls,
			DontNotifyOnChange: args.DisableNotifications,
			AutoSuspend:        args.AutoSuspend,
			AutoUnban:          !args.DontAutoUnban,
		}
		contentCopy.Lists = append(contentCopy.Lists, newList)
		_, err = ce.Meta.Bot.SendStateEvent(ce.Ctx, ce.Meta.ManagementRoom, config.StateWatchedLists, "", &contentCopy)
		if err != nil {
			ce.Reply("Failed to update watched lists: %v", err)
			return
		}
		ce.React(SuccessReaction)
	}),
}

type ListsUnsubscribeParams struct {
	Room string `json:"room_or_shortcode"`
}

var cmdListsUnsubscribe = &CommandHandler{
	Name:    "unsubscribe",
	Aliases: []string{"unwatch"},
	Parameters: []*cmdschema.Parameter{{
		Key:    "room_or_shortcode",
		Schema: cmdschema.PrimitiveTypeString.Schema(),
	}},
	Description: event.MakeExtensibleText("Unsubscribe from a policy list without leaving the room"),
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *ListsUnsubscribeParams) {
		if args.Room == "" {
			ce.Reply("Usage: `!lists unsubscribe <room ID, alias, or shortcode>`")
			return
		}
		ce.Meta.watchedListsLock.RLock()
		evtContent := ce.Meta.watchedListsEvent
		if evtContent == nil {
			ce.Meta.watchedListsLock.RUnlock()
			ce.Reply("Not subscribed to any lists")
			return
		}
		contentCopy := *evtContent
		contentCopy.Lists = slices.Clone(contentCopy.Lists)
		ce.Meta.watchedListsLock.RUnlock()
		resolvedRoom, _, _ := resolveRoomFull(ce, string(args.Room))
		if resolvedRoom == "" {
			ce.Reply("Failed to resolve room %s", format.SafeMarkdownCode(args.Room))
			return
		}
		itemIdx := -1
		for i, list := range contentCopy.Lists {
			if list.RoomID == resolvedRoom || list.Shortcode == string(args.Room) {
				itemIdx = i
				break
			}
		}
		if itemIdx < 0 {
			ce.Reply("Not subscribed to %s", format.MarkdownMentionRoomID("", resolvedRoom, ce.Meta.Bot.ServerName))
			return
		}
		contentCopy.Lists = slices.Delete(contentCopy.Lists, itemIdx, itemIdx+1)
		_, err := ce.Meta.Bot.SendStateEvent(ce.Ctx, ce.Meta.ManagementRoom, config.StateWatchedLists, "", &contentCopy)
		if err != nil {
			ce.Reply("Failed to update watched lists: %v", err)
			return
		}
		ce.React(SuccessReaction)
	}),
}

type ListsCreateParams struct {
	Name      string `json:"name"`
	Shortcode string `json:"shortcode"`
	Alias     string `json:"alias"`
	Public    bool   `json:"public"`
}

var cmdListsCreate = &CommandHandler{
	Name: "create",
	Parameters: []*cmdschema.Parameter{
		{
			Key:    "shortcode",
			Schema: cmdschema.PrimitiveTypeString.Schema(),
		},
		{
			Key:      "alias",
			Schema:   cmdschema.PrimitiveTypeString.Schema(),
			Optional: true,
		},
		{
			Key:      "name",
			Schema:   cmdschema.PrimitiveTypeString.Schema(),
			Optional: true,
		},
		{
			Key:      "public",
			Schema:   cmdschema.PrimitiveTypeBoolean.Schema(),
			Optional: true,
		},
	},
	Description: event.MakeExtensibleText("Create a policy list and subscribe to it"),
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *ListsCreateParams) {
		if args.Shortcode == "" {
			ce.Reply("Usage: `!lists create <shortcode> [--alias=localpart] [--name=room name] [--public]`")
			return
		}
		ce.Meta.watchedListsLock.Lock()
		defer ce.Meta.watchedListsLock.Unlock()
		evtContent := ce.Meta.watchedListsEvent
		if evtContent == nil {
			evtContent = &config.WatchedListsEventContent{Lists: []config.WatchedPolicyList{}}
		}
		contentCopy := *evtContent
		contentCopy.Lists = slices.Clone(contentCopy.Lists)

		for _, list := range contentCopy.Lists {
			if list.Shortcode == args.Shortcode {
				ce.Reply("Shortcode %s is already in use", format.SafeMarkdownCode(args.Shortcode))
				return
			}
		}

		zerolog.Ctx(ce.Ctx).Info().
			Str("shortcode", args.Shortcode).
			Str("alias", args.Alias).
			Str("name", args.Name).
			Bool("public", args.Public).
			Msg("Creating new policy list room")
		createReq := mautrix.ReqCreateRoom{
			Preset:        "private_chat",
			RoomAliasName: args.Alias,
			Name:          args.Name,
			Invite:        []id.UserID{ce.Event.Sender},
			RoomVersion:   id.RoomV12,
			CreationContent: map[string]any{
				"additional_creators": []id.UserID{ce.Event.Sender},
				"type":                "support.feline.policy.lists.msc.v1",
			},
			InitialState: []*event.Event{
				{
					Type:     StateMjolnirShortcode,
					StateKey: ptr.Ptr(""),
					Content:  event.Content{VeryRaw: json.RawMessage(fmt.Sprintf(`{"shortcode":"%s"}`, args.Shortcode))},
				},
			},
			PowerLevelOverride: &event.PowerLevelsEventContent{
				EventsDefault: 50,
			},
		}
		if args.Public {
			createReq.Preset = "public_chat"
		}
		roomResp, err := ce.Meta.Bot.CreateRoom(ce.Ctx, &createReq)
		if err != nil {
			ce.Reply("Failed to create list room: %v", err)
			return
		}
		newList := config.WatchedPolicyList{
			RoomID:    roomResp.RoomID,
			Shortcode: args.Shortcode,
			Name:      args.Name,
		}
		if newList.Name == "" {
			if args.Alias != "" {
				newList.Name = args.Alias
			} else {
				newList.Name = args.Shortcode
			}
		}
		contentCopy.Lists = append(contentCopy.Lists, newList)
		zerolog.Ctx(ce.Ctx).Info().Stringer("room_id", roomResp.RoomID).Msg("Created new policy list room, updating watched lists")
		_, err = ce.Meta.Bot.SendStateEvent(ce.Ctx, ce.Meta.ManagementRoom, config.StateWatchedLists, "", &contentCopy)
		md := format.MarkdownMentionRoomID(args.Name, roomResp.RoomID, ce.Meta.Bot.ServerName)
		if err != nil {
			ce.Reply("Successfully created the new list %s, but could not update watched lists: %s", md, err)
			return
		}
		ce.Reply("Created new list %s (%s)", md, format.SafeMarkdownCode(args.Shortcode))
	}),
}

var cmdLists = &CommandHandler{
	Name: "lists",
	Subcommands: []*CommandHandler{
		cmdListsSubscribe,
		cmdListsUnsubscribe,
		cmdListsCreate,
		commands.MakeUnknownCommandHandler[*PolicyEvaluator]("!"),
	},
	Aliases:     []string{"list"},
	Parameters:  make([]*cmdschema.Parameter, 0),
	Description: event.MakeExtensibleText("Display watched policy lists"),
	Func: func(ce *CommandEvent) {
		ce.Meta.watchedListsLock.RLock()
		defer ce.Meta.watchedListsLock.RUnlock()
		var builder strings.Builder
		for i, list := range ce.Meta.watchedListsEvent.Lists {
			builder.WriteString(fmt.Sprintf(
				"%d. %s - %s (%s)\n",
				i+1,
				format.SafeMarkdownCode(list.Shortcode),
				format.MarkdownMentionRoomID(list.Name, list.RoomID, ce.Meta.Bot.ServerName),
				format.SafeMarkdownCode(list.RoomID),
			))
		}
		if builder.Len() == 0 {
			ce.Reply("No lists found. Use `!lists subscribe` to add a new list.")
			return
		}
		ce.Reply(fmt.Sprintf("Watched lists (%d):\n\n%s", len(ce.Meta.watchedListsEvent.Lists), builder.String()))
	},
}

type HelpParams struct {
	Command string `json:"command"`
}

var cmdHelp = &CommandHandler{
	Name:        "help",
	Description: event.MakeExtensibleText("Show help for commands"),
	Parameters: []*cmdschema.Parameter{{
		Key:      "command",
		Schema:   cmdschema.Enum("rooms"),
		Optional: true,
	}},
	TailParam: "command",
	Func: commands.WithParsedArgs(func(ce *CommandEvent, args *HelpParams) {
		switch args.Command {
		case "rooms":
			ce.Reply(roomsHelp)
		case "lists":
			ce.Reply(listsHelp)
		case "":
			ce.Reply("Available commands:\n" +
				"* `!join <rooms...>` - Join a room\n" +
				"* `!knock <rooms...>` - Ask to join a room\n" +
				"* `!leave <rooms...>` - Leave a room\n" +
				"* `!powerlevel <room|all> <key> <level>` - Set a power level\n" +
				"* `!redact <event link or user ID> [reason]` - Redact all messages from a user\n" +
				"* `!redact-recent <room> <since duration> [reason]` - Redact all recent messages in a room\n" +
				"* `!kick [--force] [--room <room ID>] <user ID> [reason]` - Kick a user from all rooms\n" +
				"* `!ban [--hash] <list shortcode> <entity> [reason]` - Add a ban policy\n" +
				"* `!takedown [--hash] <list shortcode> <entity>` - Add a takedown policy\n" +
				"* `!remove-ban <list shortcode> <entity>` - Remove a ban policy\n" +
				"* `!add-unban <list shortcode> <entity> [reason]` - Add a ban exclusion policy\n" +
				"* `!match <entity>` - Match an entity against all lists\n" +
				"* `!search <pattern>` - Search for rules by a pattern in all lists\n" +
				"* `!send-as-bot <room> <message>` - Send a message as the bot\n" +
				"* `![un]suspend <user ID>` - Suspend or unsuspend a user\n" +
				"* `!deactivate <user ID> [--erase]` - Deactivate a user\n" +
				"* `!bot-profile <displayname/avatar> <new value>` - Update the bot profile\n" +
				"* `!rooms <...>` - Manage rooms\n" +
				"* `!version` - Check the running Meowlnir version\n" +
				"* `!lists` - Show or managed watched lists\n" +
				"* `!help <command>` - Show detailed help for a command\n" +
				"* `!help` - Show this help message\n" +
				"\n" +
				"All fields that want a room will accept both room IDs and aliases.\n",
			)
		default:
			ce.Reply("No help page for %s", format.SafeMarkdownCode(args.Command))
		}
	}),
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

func resolveRoomIDOrAlias[T ~string](ce *CommandEvent, room T) (string, []string) {
	roomID, roomAlias, via := resolveRoomFull(ce, string(room))
	if roomAlias != "" {
		return roomAlias.String(), nil
	}
	return roomID.String(), via
}

func resolveRoom[T ~string](ce *CommandEvent, room T) id.RoomID {
	roomID, _, _ := resolveRoomFull(ce, string(room))
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

func (pe *PolicyEvaluator) resolveRoomName(ctx context.Context, roomID id.RoomID) (string, error) {
	var roomName event.RoomNameEventContent
	if err := pe.Bot.StateEvent(ctx, roomID, event.StateRoomName, "", &roomName); err != nil {
		if !errors.Is(err, mautrix.MNotFound) {
			return "", fmt.Errorf("failed to get room name for %s: %w", roomID, err)
		}
	}
	if roomName.Name != "" {
		return roomName.Name, nil
	}
	var canonicalAlias event.CanonicalAliasEventContent
	if err := pe.Bot.StateEvent(ctx, roomID, event.StateCanonicalAlias, "", &canonicalAlias); err != nil {
		if !errors.Is(err, mautrix.MNotFound) {
			return "", fmt.Errorf("failed to get canonical alias for %s: %w", roomID, err)
		}
	}
	return canonicalAlias.Alias.String(), nil
}

func (pe *PolicyEvaluator) SendPolicy(ctx context.Context, policyList id.RoomID, entityType policylist.EntityType, stateKey, rawEntity string, content *event.ModPolicyContent) (*mautrix.RespSendEvent, error) {
	if stateKey == "" {
		stateKeyHash := sha256.Sum256(append([]byte(rawEntity), []byte(content.Recommendation)...))
		stateKey = base64.StdEncoding.EncodeToString(stateKeyHash[:])
	}
	return pe.Bot.SendStateEvent(ctx, policyList, entityType.EventType(), stateKey, content)
}

func init() {
	cmdRemoveBan.CopyFrom(cmdRemovePolicy)
	cmdRemoveUnban.CopyFrom(cmdRemovePolicy)
	cmdTakedown.CopyFrom(cmdBan)
	cmdRoomBlock.CopyFrom(cmdRoomDelete)
	cmdUnprotectRoom.CopyFrom(cmdProtectRoom)
	cmdUnsuspend.CopyFrom(cmdSuspend)
}
