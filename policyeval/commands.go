package policyeval

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policylist"
)

func (pe *PolicyEvaluator) HandleCommand(ctx context.Context, evt *event.Event) {
	if evt.Mautrix.WasEncrypted && evt.Mautrix.TrustState < id.TrustStateCrossSignedTOFU {
		zerolog.Ctx(ctx).Warn().
			Stringer("trust_state", evt.Mautrix.TrustState).
			Msg("Dropping encrypted event with insufficient trust state")
		return
	}
	fields := strings.Fields(evt.Content.AsMessage().Body)
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
	case "!leave":
		if len(args) == 0 {
			pe.sendNotice(ctx, "Usage: `!leave <room ID>...`")
			return
		}
		var target id.RoomID
		if strings.HasPrefix(args[0], "#") {
			rawTarget, err := pe.Bot.ResolveAlias(ctx, id.RoomAlias(args[0]))
			if err != nil {
				pe.sendNotice(ctx, "Failed to resolve alias %q: %v", args[0], err)
				return
			}
			target = rawTarget.RoomID
		} else {
			target = id.RoomID(args[0])
		}
		for _, arg := range args {
			_, err := pe.Bot.LeaveRoom(ctx, target, nil)
			if err != nil {
				pe.sendNotice(ctx, "Failed to leave room %q: %v", arg, err)
			} else {
				pe.sendNotice(ctx, "Left room %q", arg)
			}
		}
	case "!redact":
		if len(args) < 1 {
			pe.sendNotice(ctx, "Usage: `!redact <user ID> [reason]`")
			return
		}
		pe.RedactUser(ctx, id.UserID(args[0]), strings.Join(args[1:], " "), false)
		pe.sendSuccessReaction(ctx, evt.ID)
	case "!kick":
		if len(args) < 1 {
			pe.sendNotice(ctx, "Usage: `!kick <user ID> [reason]`")
			return
		}
		userID := id.UserID(args[0])
		rooms := pe.getRoomsUserIsIn(userID)
		if len(rooms) == 0 {
			pe.sendNotice(ctx, "User `%s` is not in any rooms", userID)
			return
		}
		reason := strings.Join(args[1:], " ")
		successCount := 0
		for _, room := range rooms {
			_, err := pe.Bot.KickUser(ctx, room, &mautrix.ReqKickUser{
				Reason: reason,
				UserID: userID,
			})
			if err != nil {
				pe.sendNotice(ctx, "Failed to kick `%s` from `%s`: %v", userID, room, err)
			} else {
				successCount++
			}
		}
		pe.sendSuccessReaction(ctx, evt.ID)
	case "!ban", "!ban-user", "!ban-server":
		if len(args) < 2 {
			if cmd == "!ban-server" {
				pe.sendNotice(ctx, "Usage: `!ban-server <list shortcode> <server name> <reason>`")
			} else {
				pe.sendNotice(ctx, "Usage: `!ban <list shortcode> <user ID> <reason>`")
			}
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
		if cmd == "!ban-server" {
			entityType = policylist.EntityTypeServer
			match = pe.Store.MatchServer(pe.GetWatchedLists(), target)
		} else {
			entityType = policylist.EntityTypeUser
			match = pe.Store.MatchUser(pe.GetWatchedLists(), id.UserID(target))
		}
		var existingStateKey string
		if rec := match.Recommendations().BanOrUnban; rec != nil {
			if rec.Recommendation == event.PolicyRecommendationUnban {
				pe.sendNotice(ctx, "`%s` has an unban recommendation: %s", target, rec.Reason)
				return
			} else if rec.RoomID == list.RoomID {
				existingStateKey = rec.StateKey
			}
		}
		policy := &event.ModPolicyContent{
			Entity:         target,
			Reason:         strings.Join(args[2:], " "),
			Recommendation: event.PolicyRecommendationBan,
		}
		resp, err := pe.SendPolicy(ctx, list.RoomID, entityType, existingStateKey, policy)
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
	case "!unban", "!unban-user", "!unban-server":
		if len(args) < 2 {
			if cmd == "!unban-server" {
				pe.sendNotice(ctx, "Usage: `!unban-server <list shortcode> <server name> <reason>`")
			} else {
				pe.sendNotice(ctx, "Usage: `!unban <list shortcode> <user ID> <reason>`")
			}
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
		currentlyBanned := false
		if cmd == "!unban-server" {
			entityType = policylist.EntityTypeServer
			match = pe.Store.MatchServer(pe.GetWatchedLists(), target)
		} else {
			entityType = policylist.EntityTypeUser
			match = pe.Store.MatchUser(pe.GetWatchedLists(), id.UserID(target))
		}
		var existingStateKey string
		if rec := match.Recommendations().BanOrUnban; rec != nil {
			if rec.Recommendation == event.PolicyRecommendationBan {
				currentlyBanned = true
			}
			if rec.Recommendation == event.PolicyRecommendationUnban {
				pe.sendNotice(ctx, "`%s` has an unban recommendation: %s", target, rec.Reason)
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
		if currentlyBanned {
			policy = &event.ModPolicyContent{} // just remove the ban, don't prevent it
		}
		resp, err := pe.SendPolicy(ctx, list.RoomID, entityType, existingStateKey, policy)
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
		start := time.Now()
		match := pe.Store.MatchUser(nil, id.UserID(args[0]))
		dur := time.Since(start)
		if match != nil {
			eventStrings := make([]string, len(match))
			for i, policy := range match {
				eventStrings[i] = fmt.Sprintf("* [%s](%s) set recommendation `%s` for `%s` at %s for %s",
					policy.Sender, policy.Sender.URI().MatrixToURL(), policy.Recommendation, policy.Entity, time.UnixMilli(policy.Timestamp), policy.Reason)
			}
			pe.sendNotice(ctx, "Matched in %s with recommendations %+v\n\n%s", dur, match.Recommendations(), strings.Join(eventStrings, "\n"))
		} else {
			pe.sendNotice(ctx, "No match in %s", dur.String())
		}
	}
}

func (pe *PolicyEvaluator) SendPolicy(ctx context.Context, policyList id.RoomID, entityType policylist.EntityType, stateKey string, content *event.ModPolicyContent) (*mautrix.RespSendEvent, error) {
	if stateKey == "" {
		stateKeyHash := sha256.Sum256(append([]byte(content.Entity), []byte(content.Recommendation)...))
		stateKey = base64.StdEncoding.EncodeToString(stateKeyHash[:])
	}
	return pe.Bot.SendStateEvent(ctx, policyList, entityType.EventType(), stateKey, content)
}

func (pe *PolicyEvaluator) HandleReport(ctx context.Context, sender id.UserID, roomID id.RoomID, eventID id.EventID, reason string) error {
	evt, err := pe.Bot.Client.GetEvent(ctx, roomID, eventID)
	if err != nil {
		var synErr error
		if pe.SynapseDB != nil {
			evt, synErr = pe.SynapseDB.GetEvent(ctx, eventID)
		} else {
			synErr = fmt.Errorf("synapse db not available")
		}
		if synErr != nil {
			zerolog.Ctx(ctx).
				Err(err).
				AnErr("db_error", synErr).
				Msg("Failed to get report target event from both API and database")
			pe.sendNotice(
				ctx, `[%s](%s) reported [an event](%s) for %s, but the event could not be fetched: %v`,
				sender, sender.URI().MatrixToURL(), roomID.EventURI(eventID).MatrixToURL(), reason, err,
			)
			return fmt.Errorf("failed to fetch event: %w", err)
		}
	}
	if !pe.Admins.Has(sender) || !strings.HasPrefix(reason, "/") {
		pe.sendNotice(
			ctx, `[%s](%s) reported [an event](%s) from [%s](%s) for %s`,
			sender, sender.URI().MatrixToURL(), roomID.EventURI(eventID).MatrixToURL(),
			evt.Sender, evt.Sender.URI().MatrixToURL(),
			reason,
		)
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
		match := pe.Store.MatchUser(pe.GetWatchedLists(), evt.Sender)
		if rec := match.Recommendations().BanOrUnban; rec != nil {
			if rec.Recommendation == event.PolicyRecommendationUnban {
				return mautrix.RespError{
					ErrCode:    "FI.MAU.MEOWLNIR.UNBAN_RECOMMENDED",
					Err:        fmt.Sprintf("%s has an unban recommendation: %s", evt.Sender, rec.Reason),
					StatusCode: http.StatusConflict,
				}
			} else {
				return mautrix.RespError{
					ErrCode:    "FI.MAU.MEOWLNIR.ALREADY_BANNED",
					Err:        fmt.Sprintf("%s is already banned for: %s", evt.Sender, rec.Reason),
					StatusCode: http.StatusConflict,
				}
			}
		}
		list := pe.FindListByShortcode(args[0])
		if list == nil {
			pe.sendNotice(ctx, `Failed to handle [%s](%s)'s report of [%s](%s): list %q not found`,
				sender, sender.URI().MatrixToURL(), evt.Sender, evt.Sender.URI().MatrixToURL(), args[0])
			return mautrix.MNotFound.WithMessage(fmt.Sprintf("List with shortcode %q not found", args[0]))
		}
		policy := &event.ModPolicyContent{
			Entity:         string(evt.Sender),
			Reason:         strings.Join(args[1:], " "),
			Recommendation: event.PolicyRecommendationBan,
		}
		resp, err := pe.SendPolicy(ctx, list.RoomID, policylist.EntityTypeUser, "", policy)
		if err != nil {
			pe.sendNotice(ctx, `Failed to handle [%s](%s)'s report of [%s](%s) for %s ([%s](%s)): %v`,
				sender, sender.URI().MatrixToURL(), evt.Sender, evt.Sender.URI().MatrixToURL(),
				list.Name, list.RoomID, list.RoomID.URI().MatrixToURL(), err)
			return fmt.Errorf("failed to send policy: %w", err)
		}
		zerolog.Ctx(ctx).Info().
			Stringer("policy_list", list.RoomID).
			Any("policy", policy).
			Stringer("policy_event_id", resp.EventID).
			Msg("Sent ban policy from report")
		pe.sendNotice(ctx, `Processed [%s](%s)'s report of [%s](%s) and sent a ban policy to %s ([%s](%s)) for %s`,
			sender, sender.URI().MatrixToURL(), evt.Sender, evt.Sender.URI().MatrixToURL(),
			list.Name, list.RoomID, list.RoomID.URI().MatrixToURL(), policy.Reason)
	}
	return nil
}
