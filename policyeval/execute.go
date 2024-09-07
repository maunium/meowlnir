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
	pe.usersLock.RLock()
	rooms := slices.Clone(pe.users[userID])
	pe.usersLock.RUnlock()
	return rooms
}

func (pe *PolicyEvaluator) ApplyPolicy(ctx context.Context, userID id.UserID, policy policylist.Match) {
	if userID == pe.Client.UserID {
		return
	}
	recs := policy.Recommendations()
	rooms := pe.getRoomsUserIsIn(userID)
	if recs.BanOrUnban != nil {
		if recs.BanOrUnban.Recommendation == event.PolicyRecommendationBan {
			for _, room := range rooms {
				pe.ApplyBan(ctx, userID, room, recs.BanOrUnban)
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

func (pe *PolicyEvaluator) ApplyBan(ctx context.Context, userID id.UserID, roomID id.RoomID, policy *policylist.Policy) {
	ta := &database.TakenAction{
		TargetUser: userID,
		InRoomID:   roomID,
		ActionType: database.TakenActionTypeBanOrUnban,
		PolicyList: policy.RoomID,
		RuleEntity: policy.Entity,
		Action:     policy.Recommendation,
		TakenAt:    time.Now(),
	}
	var err error
	if !pe.DryRun {
		_, err = pe.Client.BanUser(ctx, roomID, &mautrix.ReqBanUser{
			Reason: policy.Reason,
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
	if policy.Reason == "spam" {
		go pe.RedactUser(context.WithoutCancel(ctx), userID, policy.Reason)
	}
}

func pluralize(value int, unit string) string {
	if value == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", value, unit)
}

func (pe *PolicyEvaluator) RedactUser(ctx context.Context, userID id.UserID, reason string) {
	events, err := pe.SynapseDB.GetEventsToRedact(ctx, userID, pe.GetProtectedRooms())
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("user_id", userID).
			Msg("Failed to get events to redact")
		pe.sendNotice(ctx,
			"Failed to get events to redact for [%s](%s): %v",
			userID, userID.URI().MatrixToURL(), err)
		return
	} else if len(events) == 0 {
		return
	}
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
	output := fmt.Sprintf("Redacted %s across %s from [%s](%s)",
		pluralize(redactedCount, "event"), pluralize(len(events), "room"),
		userID, userID.URI().MatrixToURL())
	if len(errorMessages) > 0 {
		output += "\n\n" + strings.Join(errorMessages, "\n")
	}
	pe.sendNotice(ctx, output)
}

func (pe *PolicyEvaluator) redactEventsInRoom(ctx context.Context, userID id.UserID, roomID id.RoomID, events []id.EventID, reason string) (successCount, failedCount int) {
	for _, evtID := range events {
		var resp *mautrix.RespSendEvent
		var err error
		if !pe.DryRun {
			resp, err = pe.Client.RedactEvent(ctx, roomID, evtID, mautrix.ReqRedact{Reason: reason})
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