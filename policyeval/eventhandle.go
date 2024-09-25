package policyeval

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
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
		errorMsg = pe.handlePowerLevels(evt)
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
		pe.protectedRoomsLock.RUnlock()
		if isProtecting && (content.Membership == event.MembershipLeave || content.Membership == event.MembershipBan) {
			pe.sendNotice(ctx, "⚠️ Bot was removed from [%s](%s)", evt.RoomID, evt.RoomID.URI().MatrixToURL())
		} else if wantToProtect && (content.Membership == event.MembershipJoin || content.Membership == event.MembershipInvite) {
			_, err := pe.Bot.JoinRoomByID(ctx, evt.RoomID)
			if err != nil {
				pe.sendNotice(ctx, "Failed to join room [%s](%s): %v", evt.RoomID, evt.RoomID.URI().MatrixToURL(), err)
			} else if _, errMsg := pe.tryProtectingRoom(ctx, nil, evt.RoomID, true); errMsg != "" {
				pe.sendNotice(ctx, "Retried protecting room after joining room, but failed: %s", strings.TrimPrefix(errMsg, "* "))
			} else {
				pe.sendNotice(ctx, "Bot was invited to room, now protecting [%s](%s)", evt.RoomID, evt.RoomID.URI().MatrixToURL())
			}
		}
	} else {
		checkRules := pe.updateUser(userID, evt.RoomID, content.Membership)
		if checkRules {
			pe.EvaluateUser(ctx, userID)
		}
	}
}

func addActionString(rec event.PolicyRecommendation) string {
	switch rec {
	case event.PolicyRecommendationBan:
		return "banned"
	case event.PolicyRecommendationUnban:
		return "added a ban exclusion for"
	default:
		return fmt.Sprintf("added a `%s` rule for", rec)
	}
}

func changeActionString(rec event.PolicyRecommendation) string {
	switch rec {
	case event.PolicyRecommendationBan:
		return "ban"
	case event.PolicyRecommendationUnban:
		return "ban exclusion"
	default:
		return fmt.Sprintf("`%s`", rec)
	}
}

func removeActionString(rec event.PolicyRecommendation) string {
	switch rec {
	case event.PolicyRecommendationBan:
		return "unbanned"
	case event.PolicyRecommendationUnban:
		return "removed a ban exclusion for"
	default:
		return fmt.Sprintf("removed a `%s` rule for", rec)
	}
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
	removedAndAddedAreEquivalent := removed != nil && added != nil && removed.Entity == added.Entity && removed.Recommendation == added.Recommendation
	if removedAndAddedAreEquivalent {
		if removed.Reason == added.Reason {
			pe.sendNotice(ctx,
				"[%s] [%s](%s) re-%s `%s` for `%s`",
				policyRoomMeta.Name, added.Sender, added.Sender.URI().MatrixToURL(),
				addActionString(added.Recommendation), added.Entity, added.Reason)
		} else {
			pe.sendNotice(ctx,
				"[%s] [%s](%s) changed the %s reason for `%s` from `%s` to `%s`",
				policyRoomMeta.Name, added.Sender, added.Sender.URI().MatrixToURL(),
				changeActionString(added.Recommendation), added.Entity, removed.Reason, added.Reason)
		}
	} else {
		if removed != nil {
			pe.sendNotice(ctx,
				"[%s] [%s](%s) %s %ss matching `%s` for %s",
				policyRoomMeta.Name, removed.Sender, removed.Sender.URI().MatrixToURL(),
				removeActionString(removed.Recommendation), removed.EntityType, removed.Entity, removed.Reason,
			)
			if !policyRoomMeta.DontApply {
				pe.EvaluateRemovedRule(ctx, removed)
			}
		}
		if added != nil {
			var suffix string
			if added.Ignored {
				suffix = " (rule was ignored)"
			}
			pe.sendNotice(ctx,
				"[%s] [%s](%s) %s %ss matching `%s` for %s%s",
				policyRoomMeta.Name, added.Sender, added.Sender.URI().MatrixToURL(),
				addActionString(added.Recommendation), added.EntityType, added.Entity, added.Reason,
				suffix,
			)
			if !policyRoomMeta.DontApply {
				pe.EvaluateAddedRule(ctx, added)
			}
		}
	}
}
