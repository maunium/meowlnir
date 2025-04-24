package policyeval

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/database"
	"go.mau.fi/meowlnir/policylist"
)

func (pe *PolicyEvaluator) getRoomsUserIsIn(userID id.UserID) []id.RoomID {
	pe.protectedRoomsLock.RLock()
	rooms := slices.Clone(pe.protectedRoomMembers[userID])
	pe.protectedRoomsLock.RUnlock()
	return rooms
}

func (pe *PolicyEvaluator) ApplyPolicy(ctx context.Context, userID id.UserID, policy policylist.Match, isNew bool) {
	if userID == pe.Bot.UserID {
		return
	}
	recs := policy.Recommendations()
	rooms := pe.getRoomsUserIsIn(userID)
	if !isNew && len(rooms) == 0 {
		// Don't apply policies to left users when re-evaluating rules,
		// because it would lead to unnecessarily scanning for events to redact.
		// Left users do need to be scanned when a new rule is added though
		// in case they spammed and left right before getting banned.
		return
	}
	if recs.BanOrUnban != nil {
		if recs.BanOrUnban.Recommendation == event.PolicyRecommendationBan || recs.BanOrUnban.Recommendation == event.PolicyRecommendationUnstableTakedown {
			zerolog.Ctx(ctx).Info().
				Stringer("user_id", userID).
				Any("matches", policy).
				Msg("Applying ban recommendation")
			for _, room := range rooms {
				pe.ApplyBan(ctx, userID, room, recs.BanOrUnban)
			}
			shouldRedact := recs.BanOrUnban.Recommendation == event.PolicyRecommendationUnstableTakedown
			if !shouldRedact && recs.BanOrUnban.Reason != "" {
				for _, pattern := range pe.autoRedactPatterns {
					if pattern.Match(recs.BanOrUnban.Reason) {
						shouldRedact = true
						break
					}
				}
			}
			if shouldRedact {
				go pe.RedactUser(context.WithoutCancel(ctx), userID, recs.BanOrUnban.Reason, true)
			}
			if isNew {
				go pe.RejectPendingInvites(context.WithoutCancel(ctx), userID, recs.BanOrUnban)
			}
		} else {
			// TODO unban if banned in some rooms? or just require doing that manually
			//takenActions, err := pe.DB.TakenAction.GetAllByTargetUser(ctx, userID, database.TakenActionTypeBanOrUnban)
			//if err != nil {
			//	zerolog.Ctx(ctx).Err(err).Stringer("user_id", userID).Msg("Failed to get taken actions")
			//	pe.sendNotice(ctx, "Database error in ApplyPolicy (GetAllByTargetUser): %v", err)
			//	return
			//}
		}
	}
}

func filterReason(reason string) string {
	if reason == "<no reason supplied>" {
		return ""
	}
	return reason
}

func (pe *PolicyEvaluator) ApplyBan(ctx context.Context, userID id.UserID, roomID id.RoomID, policy *policylist.Policy) {
	ta := &database.TakenAction{
		TargetUser: userID,
		InRoomID:   roomID,
		ActionType: database.TakenActionTypeBanOrUnban,
		PolicyList: policy.RoomID,
		RuleEntity: policy.EntityOrHash(),
		Action:     policy.Recommendation,
		TakenAt:    time.Now(),
	}
	var err error
	if !pe.DryRun {
		_, err = pe.Bot.BanUser(ctx, roomID, &mautrix.ReqBanUser{
			Reason: filterReason(policy.Reason),
			UserID: userID,
		})
	}
	if err != nil {
		var respErr mautrix.HTTPError
		if errors.As(err, &respErr) {
			err = respErr
		}
		zerolog.Ctx(ctx).Err(err).Any("attempted_action", ta).Msg("Failed to ban user")
		pe.sendNotice(ctx, "Failed to ban [%s](%s) in [%s](%s) for %s: %v", userID, userID.URI().MatrixToURL(), roomID, roomID.URI().MatrixToURL(), policy.Reason, err)
		return
	}
	err = pe.DB.TakenAction.Put(ctx, ta)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Any("taken_action", ta).Msg("Failed to save taken action")
		pe.sendNotice(ctx, "Banned [%s](%s) in [%s](%s) for %s, but failed to save to database: %v", userID, userID.URI().MatrixToURL(), roomID, roomID.URI().MatrixToURL(), policy.Reason, err)
	} else {
		zerolog.Ctx(ctx).Info().Any("taken_action", ta).Msg("Took action")
		pe.sendNotice(ctx, "Banned [%s](%s) in [%s](%s) for %s", userID, userID.URI().MatrixToURL(), roomID, roomID.URI().MatrixToURL(), policy.Reason)
	}
}

func (pe *PolicyEvaluator) UndoBan(ctx context.Context, userID id.UserID, roomID id.RoomID) bool {
	if !pe.DryRun && !pe.Bot.StateStore.IsMembership(ctx, roomID, userID, event.MembershipBan) {
		zerolog.Ctx(ctx).Trace().Msg("User is not banned in room, skipping unban")
		return true
	}

	var err error
	if !pe.DryRun {
		_, err = pe.Bot.UnbanUser(ctx, roomID, &mautrix.ReqUnbanUser{
			UserID: userID,
		})
	}
	if err != nil {
		var respErr mautrix.HTTPError
		if errors.As(err, &respErr) {
			err = respErr
		}
		zerolog.Ctx(ctx).Err(err).Msg("Failed to unban user")
		pe.sendNotice(ctx, "Failed to unban [%s](%s) in [%s](%s): %v", userID, userID.URI().MatrixToURL(), roomID, roomID.URI().MatrixToURL(), err)
		return false
	}
	zerolog.Ctx(ctx).Debug().Msg("Unbanned user")
	pe.sendNotice(ctx, "Unbanned [%s](%s) in [%s](%s)", userID, userID.URI().MatrixToURL(), roomID, roomID.URI().MatrixToURL())
	return true
}

func pluralize(value int, unit string) string {
	if value == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", value, unit)
}

func (pe *PolicyEvaluator) redactUserMSC4194(ctx context.Context, userID id.UserID, reason string) {
	rooms := pe.GetProtectedRooms()
	var errorMessages []string
	var redactedCount, roomCount int
Outer:
	for _, roomID := range rooms {
		hasMore := true
		roomCounted := false
		for hasMore {
			resp, err := pe.Bot.UnstableRedactUserEvents(ctx, roomID, userID, &mautrix.ReqRedactUser{Reason: reason})
			if err != nil {
				zerolog.Ctx(ctx).Err(err).Stringer("room_id", roomID).Msg("Failed to redact messages")
				errorMessages = append(errorMessages, fmt.Sprintf(
					"* Failed to redact events from [%s](%s) in [%s](%s): %v",
					userID, userID.URI().MatrixToURL(), roomID, roomID.URI().MatrixToURL(), err))
				continue Outer
			}
			hasMore = resp.IsMoreEvents
			if resp.RedactedEvents.Total > 0 {
				redactedCount += resp.RedactedEvents.Total
				if !roomCounted {
					roomCount++
					roomCounted = true
				}
			}
		}
	}
	pe.sendRedactResult(ctx, redactedCount, roomCount, userID, errorMessages)
}

func (pe *PolicyEvaluator) redactUserSynapse(ctx context.Context, userID id.UserID, reason string, allowReredact bool) {
	start := time.Now()
	events, maxTS, err := pe.SynapseDB.GetEventsToRedact(ctx, userID, pe.GetProtectedRooms())
	dur := time.Since(start)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("user_id", userID).
			Dur("query_duration", dur).
			Msg("Failed to get events to redact")
		pe.sendNotice(ctx,
			"Failed to get events to redact for [%s](%s): %v",
			userID, userID.URI().MatrixToURL(), err)
		return
	} else if len(events) == 0 {
		zerolog.Ctx(ctx).Debug().
			Stringer("user_id", userID).
			Str("reason", reason).
			Bool("allow_redact", allowReredact).
			Dur("query_duration", dur).
			Msg("No events found to redact")
		return
	}
	reason = filterReason(reason)
	needsReredact := allowReredact && time.Since(maxTS) < 5*time.Minute
	zerolog.Ctx(ctx).Debug().
		Stringer("user_id", userID).
		Int("event_count", len(events)).
		Time("max_ts", maxTS).
		Bool("needs_redact", needsReredact).
		Str("reason", reason).
		Dur("query_duration", dur).
		Msg("Got events to redact")
	var errorMessages []string
	var redactedCount int
	for roomID, roomEvents := range events {
		successCount, failedCount := pe.redactEventsInRoom(ctx, userID, roomID, roomEvents, reason)
		if failedCount > 0 {
			errorMessages = append(errorMessages, fmt.Sprintf(
				"* Failed to redact %d/%d events from [%s](%s) in [%s](%s)",
				failedCount, failedCount+successCount, userID, userID.URI().MatrixToURL(), roomID, roomID.URI().MatrixToURL()))
		}
		redactedCount += successCount
	}
	pe.sendRedactResult(ctx, redactedCount, len(events), userID, errorMessages)
	if needsReredact {
		time.Sleep(15 * time.Second)
		zerolog.Ctx(ctx).Debug().
			Stringer("user_id", userID).
			Msg("Re-redacting user to ensure soft-failed events get redacted")
		pe.RedactUser(ctx, userID, reason, false)
	}
}

func (pe *PolicyEvaluator) sendRedactResult(ctx context.Context, events, rooms int, userID id.UserID, errorMessages []string) {
	output := fmt.Sprintf("Redacted %s across %s from [%s](%s)",
		pluralize(events, "event"), pluralize(rooms, "room"),
		userID, userID.URI().MatrixToURL())
	if len(errorMessages) > 0 {
		output += "\n\n" + strings.Join(errorMessages, "\n")
	}
	pe.sendNotice(ctx, output)
}

func (pe *PolicyEvaluator) RedactUser(ctx context.Context, userID id.UserID, reason string, allowReredact bool) {
	if pe.SynapseDB != nil {
		pe.redactUserSynapse(ctx, userID, reason, allowReredact)
	} else if pe.Bot.Client.SpecVersions.Supports(mautrix.FeatureUserRedaction) {
		pe.redactUserMSC4194(ctx, userID, reason)
	} else {
		zerolog.Ctx(ctx).Warn().
			Stringer("user_id", userID).
			Msg("Falling back to history iteration based event discovery for redaction. This is slow.")
		for _, roomID := range pe.GetProtectedRooms() {
			redactedCount, err := pe.redactRecentMessages(ctx, roomID, userID, 24*time.Hour, true, reason)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).
					Stringer("user_id", userID).
					Stringer("room_id", roomID).
					Msg("Failed to redact recent messages")
				continue
			}
			pe.sendNotice(ctx, "Redacted %d events from [%s](%s) in [%s](%s)", redactedCount, userID, userID.URI().MatrixToURL(), roomID, roomID.URI().MatrixToURL())
		}
	}
}

func (pe *PolicyEvaluator) redactEventsInRoom(ctx context.Context, userID id.UserID, roomID id.RoomID, events []id.EventID, reason string) (successCount, failedCount int) {
	for _, evtID := range events {
		var resp *mautrix.RespSendEvent
		var err error
		if !pe.DryRun {
			resp, err = pe.Bot.RedactEvent(ctx, roomID, evtID, mautrix.ReqRedact{Reason: reason})
		} else {
			resp = &mautrix.RespSendEvent{EventID: "$fake-redaction-id"}
		}
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Stringer("sender", userID).
				Stringer("room_id", roomID).
				Stringer("event_id", evtID).
				Msg("Failed to redact event")
			failedCount++
		} else {
			zerolog.Ctx(ctx).Debug().
				Stringer("sender", userID).
				Stringer("room_id", roomID).
				Stringer("event_id", evtID).
				Stringer("redaction_id", resp.EventID).
				Msg("Successfully redacted event")
			successCount++
		}
	}
	return
}

func (pe *PolicyEvaluator) redactRecentMessages(ctx context.Context, roomID id.RoomID, sender id.UserID, maxAge time.Duration, redactState bool, reason string) (int, error) {
	var pls event.PowerLevelsEventContent
	err := pe.Bot.StateEvent(ctx, roomID, event.StatePowerLevels, "", &pls)
	if err != nil {
		return 0, fmt.Errorf("failed to get power levels: %w", err)
	}
	minTS := time.Now().Add(-maxAge).UnixMilli()
	var sinceToken string
	var redactedCount int
	for {
		events, err := pe.Bot.Messages(ctx, roomID, sinceToken, "", mautrix.DirectionBackward, nil, 50)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Stringer("room_id", roomID).
				Str("since_token", sinceToken).
				Msg("Failed to get recent messages")
			return redactedCount, fmt.Errorf("failed to get messages: %w", err)
		}
		for _, evt := range events.Chunk {
			if evt.Timestamp < minTS {
				return redactedCount, nil
			} else if (evt.StateKey != nil && !redactState) ||
				evt.Type == event.EventRedaction ||
				pls.GetUserLevel(evt.Sender) >= pls.Redact() ||
				evt.Unsigned.RedactedBecause != nil {
				continue
			}
			if sender != "" && evt.Sender != sender {
				continue
			}
			resp, err := pe.Bot.RedactEvent(ctx, roomID, evt.ID, mautrix.ReqRedact{Reason: reason})
			if err != nil {
				zerolog.Ctx(ctx).Err(err).
					Stringer("room_id", roomID).
					Stringer("event_id", evt.ID).
					Msg("Failed to redact event")
			} else {
				zerolog.Ctx(ctx).Debug().
					Stringer("room_id", roomID).
					Stringer("event_id", evt.ID).
					Stringer("redaction_id", resp.EventID).
					Msg("Successfully redacted event")
				redactedCount++
			}
		}
		sinceToken = events.End
		if sinceToken == "" {
			break
		}
	}
	return redactedCount, nil
}
