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
	var errorMsg string
	switch evt.Type {
	case event.StatePowerLevels:
		errorMsg = pe.handlePowerLevels(evt)
	case config.StateWatchedLists:
		errorMsgs := pe.handleWatchedLists(ctx, evt, false)
		errorMsg = strings.Join(errorMsgs, "\n")
	case config.StateProtectedRooms:
		errorMsgs := pe.handleProtectedRooms(ctx, evt, false)
		errorMsg = strings.Join(errorMsgs, "\n")
	}
	if errorMsg != "" {
		pe.sendNotice(ctx, "Errors occurred while handling config change:\n\n%s", errorMsg)
	}
}

func (pe *PolicyEvaluator) HandleMember(ctx context.Context, evt *event.Event) {
	checkRules := pe.updateUser(id.UserID(evt.GetStateKey()), evt.RoomID, evt.Content.AsMember().Membership)
	if checkRules {
		pe.EvaluateUser(ctx, id.UserID(evt.GetStateKey()))
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
		Any("added", added).
		Any("removed", removed).
		Msg("Policy list change")
	removedAndAddedAreEquivalent := removed != nil && added != nil && removed.Entity == added.Entity && removed.Recommendation == added.Recommendation
	if removedAndAddedAreEquivalent {
		pe.sendNotice(ctx,
			"[%s] [%s](%s) changed the %s reason for `%s` from `%s` to `%s`",
			policyRoomMeta.Name, added.Sender, added.Sender.URI().MatrixToURL(),
			changeActionString(added.Recommendation), added.Entity, removed.Reason, added.Reason)
	} else {
		if removed != nil {
			pe.sendNotice(ctx,
				"[%s] [%s](%s) %s %ss matching `%s` for %s",
				policyRoomMeta.Name, removed.Sender, removed.Sender.URI().MatrixToURL(),
				removeActionString(removed.Recommendation), removed.EntityType, removed.Entity, removed.Reason,
			)
			pe.EvaluateRemovedRule(ctx, removed)
		}
		if added != nil {
			pe.sendNotice(ctx,
				"[%s] [%s](%s) %s %ss matching `%s` for %s",
				policyRoomMeta.Name, added.Sender, added.Sender.URI().MatrixToURL(),
				addActionString(added.Recommendation), added.EntityType, added.Entity, added.Reason,
			)
			pe.EvaluateAddedRule(ctx, added)
		}
	}
}
