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
	fields := strings.Fields(evt.Content.AsMessage().Body)
	cmd := fields[0]
	args := fields[1:]
	zerolog.Ctx(ctx).Info().Str("command", cmd).Msg("Handling command")
	switch strings.ToLower(cmd) {
	case "!join":
		for _, arg := range args {
			pe.Bot.JoinRoom(ctx, arg, "", nil)
		}
	case "!redact":
		pe.RedactUser(ctx, id.UserID(args[0]), strings.Join(args[1:], " "), false)
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

func (pe *PolicyEvaluator) SendPolicy(ctx context.Context, policyList id.RoomID, entityType policylist.EntityType, content *event.ModPolicyContent) (*mautrix.RespSendEvent, error) {
	stateKeyHash := sha256.Sum256(append([]byte(content.Entity), []byte(content.Recommendation)...))
	return pe.Bot.SendStateEvent(ctx, policyList, entityType.EventType(), base64.StdEncoding.EncodeToString(stateKeyHash[:]), content)
}

func (pe *PolicyEvaluator) HandleReport(ctx context.Context, sender id.UserID, roomID id.RoomID, eventID id.EventID, reason string) error {
	evt, err := pe.Bot.Client.GetEvent(ctx, roomID, eventID)
	if err != nil {
		var synErr error
		evt, synErr = pe.SynapseDB.GetEvent(ctx, eventID)
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
		resp, err := pe.SendPolicy(ctx, list.RoomID, policylist.EntityTypeUser, policy)
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
