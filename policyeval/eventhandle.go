package policyeval

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exfmt"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/config"
	"go.mau.fi/meowlnir/policylist"
)

func (pe *PolicyEvaluator) HandleConfigChange(ctx context.Context, evt *event.Event) {
	pe.configLock.Lock()
	defer pe.configLock.Unlock()
	var errorMsg, successMsg string
	switch evt.Type {
	case event.StatePowerLevels:
		_, errorMsg = pe.handlePowerLevels(ctx, evt)
	case config.StateWatchedLists:
		successMsgs, errorMsgs := pe.handleWatchedLists(ctx, evt, false)
		successMsg = strings.Join(successMsgs, "\n")
		errorMsg = strings.Join(errorMsgs, "\n")
	case config.StateProtectedRooms:
		successMsgs, errorMsgs := pe.handleProtectedRooms(ctx, evt, false)
		successMsg = strings.Join(successMsgs, "\n")
		errorMsg = strings.Join(errorMsgs, "\n")
	}
	var output string
	if successMsg != "" {
		if errorMsg != "" {
			output = fmt.Sprintf("Handled `%s` event with errors:\n\n%s\n%s", evt.Type.Type, successMsg, errorMsg)
		} else {
			output = fmt.Sprintf("Successfully handled `%s` event:\n\n%s", evt.Type.Type, successMsg)
		}
	} else if errorMsg != "" {
		output = fmt.Sprintf("Failed to handle `%s` event:\n\n%s", evt.Type.Type, errorMsg)
	}
	if output != "" {
		pe.sendNotice(ctx, output)
	}
}

func (pe *PolicyEvaluator) HandleMember(ctx context.Context, evt *event.Event) {
	userID := id.UserID(evt.GetStateKey())
	content := evt.Content.AsMember()
	if userID == pe.Bot.UserID {
		pe.protectedRoomsLock.RLock()
		_, isProtecting := pe.protectedRooms[evt.RoomID]
		_, wantToProtect := pe.wantToProtect[evt.RoomID]
		_, isJoining := pe.isJoining[evt.RoomID]
		pe.protectedRoomsLock.RUnlock()
		if isJoining {
			return
		}
		if isProtecting && (content.Membership == event.MembershipLeave || content.Membership == event.MembershipBan) {
			pe.sendNotice(ctx, "⚠️ Bot was removed from %s", pe.markdownMentionRoom(ctx, evt.RoomID, evt.Sender.Homeserver()))
		} else if wantToProtect && (content.Membership == event.MembershipJoin || content.Membership == event.MembershipInvite) {
			_, err := pe.Bot.JoinRoomByID(ctx, evt.RoomID)
			if err != nil {
				pe.sendNotice(
					ctx,
					"Failed to join room %s: %v",
					pe.markdownMentionRoom(ctx, evt.RoomID, evt.Sender.Homeserver()),
					err,
				)
			} else if _, errMsg := pe.tryProtectingRoom(ctx, nil, evt.RoomID, true); errMsg != "" {
				pe.sendNotice(
					ctx,
					"Retried protecting %s after joining, but failed: %s",
					pe.markdownMentionRoom(ctx, evt.RoomID),
					strings.TrimPrefix(errMsg, "* "),
				)
			} else {
				pe.sendNotice(
					ctx,
					"Bot was invited to room, now protecting %s",
					pe.markdownMentionRoom(ctx, evt.RoomID),
				)
			}
		}
	} else {
		checkRules := pe.updateUser(userID, evt.RoomID, content.Membership)
		if checkRules {
			pe.EvaluateUser(ctx, userID, false)
		}
		if pe.ShouldExecuteProtections(ctx, evt) {
			for _, prot := range pe.protections {
				_, err := prot.Execute(ctx, pe, evt, pe.DryRun)
				if err != nil {
					zerolog.Ctx(ctx).Err(err).Msg("Error executing protection")
				}
			}
		}
	}
}

func addActionString(rec event.PolicyRecommendation) string {
	switch rec {
	case event.PolicyRecommendationBan, event.PolicyRecommendationUnstableTakedown:
		return "banned"
	case event.PolicyRecommendationUnban:
		return "added a ban exclusion for"
	default:
		return fmt.Sprintf("added a `%s` rule for", rec)
	}
}

func changeActionString(rec event.PolicyRecommendation) string {
	switch rec {
	case event.PolicyRecommendationBan, event.PolicyRecommendationUnstableTakedown:
		return "ban"
	case event.PolicyRecommendationUnban:
		return "ban exclusion"
	default:
		return fmt.Sprintf("`%s`", rec)
	}
}

func removeActionString(rec event.PolicyRecommendation) string {
	switch rec {
	case event.PolicyRecommendationBan, event.PolicyRecommendationUnstableTakedown:
		return "unbanned"
	case event.PolicyRecommendationUnban:
		return "removed a ban exclusion for"
	default:
		return fmt.Sprintf("removed a `%s` rule for", rec)
	}
}

func noopSendNotice(_ context.Context, _ string, _ ...any) id.EventID { return "" }

func oldEventNotice(timestamp int64) string {
	age := time.Since(time.UnixMilli(timestamp))
	if age > 5*time.Minute {
		return fmt.Sprintf(" %s ago", exfmt.DurationCustom(age, nil, exfmt.Day, time.Hour, time.Minute))
	}
	return ""
}

func (pe *PolicyEvaluator) HandlePolicyListChange(ctx context.Context, policyRoom id.RoomID, added, removed *policylist.Policy) {
	policyRoomMeta := pe.GetWatchedListMeta(policyRoom)
	if policyRoomMeta == nil {
		return
	}
	zerolog.Ctx(ctx).Info().
		Bool("dont_apply", policyRoomMeta.DontApply).
		Any("added", added).
		Any("removed", removed).
		Msg("Policy list change")
	removedAndAddedAreEquivalent := removed != nil && added != nil && removed.EntityOrHash() == added.EntityOrHash() && removed.Recommendation == added.Recommendation
	sendNotice := pe.sendNotice
	if policyRoomMeta.DontNotifyOnChange {
		sendNotice = noopSendNotice
	}
	if removedAndAddedAreEquivalent {
		if removed.Reason == added.Reason {
			sendNotice(ctx,
				"[%s] %s re-%s ||`%s`|| for `%s`%s",
				policyRoomMeta.Name, format.MarkdownMention(added.Sender),
				addActionString(added.Recommendation), added.EntityOrHash(), added.Reason,
				oldEventNotice(added.Timestamp),
			)
		} else {
			sendNotice(ctx,
				"[%s] %s changed the %s reason for ||`%s`|| from `%s` to `%s`%s",
				policyRoomMeta.Name, format.MarkdownMention(added.Sender),
				changeActionString(added.Recommendation), added.EntityOrHash(), removed.Reason, added.Reason,
				oldEventNotice(added.Timestamp),
			)
		}
	} else {
		if removed != nil {
			sendNotice(ctx,
				"[%s] %s %s %ss matching ||`%s`|| for `%s`%s",
				policyRoomMeta.Name, format.MarkdownMention(removed.Sender),
				removeActionString(removed.Recommendation), removed.EntityType, removed.EntityOrHash(), removed.Reason,
				oldEventNotice(removed.Timestamp),
			)
			if !policyRoomMeta.DontApply {
				pe.EvaluateRemovedRule(ctx, removed)
			}
		}
		if added != nil {
			suffix := oldEventNotice(added.Timestamp)
			if added.Ignored {
				suffix += " (rule was ignored)"
			}
			sendNotice(ctx,
				"[%s] %s %s %ss matching ||`%s`|| for `%s`%s",
				policyRoomMeta.Name, format.MarkdownMention(added.Sender),
				addActionString(added.Recommendation), added.EntityType, added.EntityOrHash(), added.Reason,
				suffix,
			)
			if !policyRoomMeta.DontApply {
				pe.EvaluateAddedRule(ctx, added)
			}
		}
	}
}
