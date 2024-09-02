package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/config"
)

func (m *Meowlnir) AddEventHandlers() {
	m.EventProcessor.On(event.StatePolicyUser, m.UpdatePolicyList)
	m.EventProcessor.On(event.StatePolicyRoom, m.UpdatePolicyList)
	m.EventProcessor.On(event.StatePolicyServer, m.UpdatePolicyList)
	m.EventProcessor.On(event.StateLegacyPolicyUser, m.UpdatePolicyList)
	m.EventProcessor.On(event.StateLegacyPolicyRoom, m.UpdatePolicyList)
	m.EventProcessor.On(event.StateLegacyPolicyServer, m.UpdatePolicyList)
	m.EventProcessor.On(event.StateUnstablePolicyUser, m.UpdatePolicyList)
	m.EventProcessor.On(event.StateUnstablePolicyRoom, m.UpdatePolicyList)
	m.EventProcessor.On(event.StateUnstablePolicyServer, m.UpdatePolicyList)
	m.EventProcessor.On(event.StateMember, m.HandleMember)
	m.EventProcessor.On(config.StateWatchedLists, m.HandleConfigChange)
	m.EventProcessor.On(config.StateProtectedRooms, m.HandleConfigChange)
	m.EventProcessor.On(event.StatePowerLevels, m.HandleConfigChange)
	m.EventProcessor.On(event.EventMessage, m.HandleCommand)
}

func (m *Meowlnir) UpdatePolicyList(ctx context.Context, evt *event.Event) {
	added, removed := m.PolicyStore.Update(evt)
	for _, eval := range m.EvaluatorByManagementRoom {
		eval.HandlePolicyListChange(ctx, evt.RoomID, added, removed)
	}
}

func (m *Meowlnir) HandleConfigChange(ctx context.Context, evt *event.Event) {
	m.EvaluatorLock.RLock()
	roomProtector, ok := m.EvaluatorByProtectedRoom[evt.RoomID]
	m.EvaluatorLock.RUnlock()
	if ok {
		roomProtector.HandleConfigChange(ctx, evt)
	}
}

func (m *Meowlnir) HandleMember(ctx context.Context, evt *event.Event) {
	content, ok := evt.Content.Parsed.(*event.MemberEventContent)
	if !ok {
		return
	}
	if evt.GetStateKey() == m.Client.UserID.String() {
		managementRoom, ok := m.EvaluatorByManagementRoom[evt.RoomID]
		if ok && content.Membership == event.MembershipInvite {
			_, err := m.Client.JoinRoomByID(ctx, evt.RoomID)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).
					Stringer("room_id", evt.RoomID).
					Stringer("inviter", evt.Sender).
					Msg("Failed to join management room after invite")
			} else {
				zerolog.Ctx(ctx).Info().
					Stringer("room_id", evt.RoomID).
					Stringer("inviter", evt.Sender).
					Msg("Joined management room after invite, loading room state")
				managementRoom.Load(ctx)
			}
		}
		return
	}
	m.EvaluatorLock.RLock()
	roomProtector, ok := m.EvaluatorByProtectedRoom[evt.RoomID]
	m.EvaluatorLock.RUnlock()
	if ok {
		roomProtector.HandleMember(ctx, evt)
	}
}

func (m *Meowlnir) HandleCommand(ctx context.Context, evt *event.Event) {
	room, ok := m.EvaluatorByManagementRoom[evt.RoomID]
	if !ok || !room.Admins.Has(evt.Sender) {
		return
	}
	fields := strings.Fields(evt.Content.AsMessage().Body)
	cmd := fields[0]
	args := fields[1:]
	m.Log.Info().Str("command", cmd).Msg("Handling command")
	switch strings.ToLower(cmd) {
	case "!join":
		for _, arg := range args {
			m.Client.JoinRoomByID(ctx, id.RoomID(arg))
		}
	case "!match":
		start := time.Now()
		match := m.PolicyStore.MatchUser(nil, id.UserID(args[0]))
		dur := time.Since(start)
		if match != nil {
			eventStrings := make([]string, len(match))
			for i, policy := range match {
				eventStrings[i] = fmt.Sprintf("* [%s](%s) set recommendation `%s` for `%s` at %s for %s",
					policy.Sender, policy.Sender.URI().MatrixToURL(), policy.Recommendation, policy.Entity, time.UnixMilli(policy.Timestamp), policy.Reason)
			}
			reply := fmt.Sprintf("Matched in %s with recommendations %+v\n\n%s", dur, match.Recommendations(), strings.Join(eventStrings, "\n"))
			m.Client.SendMessageEvent(ctx, evt.RoomID, event.EventMessage, format.RenderMarkdown(reply, true, false))
		} else {
			m.Client.SendNotice(ctx, evt.RoomID, "No match in "+dur.String())
		}
	}
}
