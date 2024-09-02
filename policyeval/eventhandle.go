package policyeval

import (
	"context"
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
		pe.EvaluateNewMember(ctx, id.UserID(evt.GetStateKey()))
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
	if removed != nil && added != nil && removed.Entity == added.Entity {
		// probably just a reason change (unless recommendation changed too)
	}
	if removed != nil && (added == nil || removed.Entity != added.Entity) {
		pe.EvaluateRemovedRule(ctx, removed)
		// TODO include entity type in message
		pe.sendNotice(ctx,
			"[%s](%s) (%s): [%s](%s) removed `%s`/`%s` rule matching `%s` for %s",
			policyRoomMeta.Name, policyRoom.URI().MatrixToURL(), policyRoomMeta.Name,
			removed.Sender, removed.Sender.URI().MatrixToURL(),
			removed.EntityType, removed.Recommendation, removed.Entity, removed.Reason,
		)
	}
	if added != nil && (removed == nil || removed.Entity != added.Entity) {
		pe.EvaluateAddedRule(ctx, added)
		// TODO include entity type in message
		pe.sendNotice(ctx,
			"[%s](%s) (%s): [%s](%s) added `%s`/`%s` rule matching `%s` for %s",
			policyRoomMeta.Name, policyRoom.URI().MatrixToURL(), policyRoomMeta.Name,
			added.Sender, added.Sender.URI().MatrixToURL(),
			added.EntityType, added.Recommendation, added.Entity, added.Reason,
		)
	}
}
