package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policylist"
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
	m.EventProcessor.On(event.EventMessage, m.HandleCommand)
}

func (m *Meowlnir) UpdatePolicyList(ctx context.Context, evt *event.Event) {
	added, removed := m.PolicyStore.Update(evt)
	fmt.Println(added, removed)
}

const tempAdmin = "@tulir:maunium.net"

func (m *Meowlnir) HandleMember(ctx context.Context, evt *event.Event) {
	content, ok := evt.Content.Parsed.(*event.MemberEventContent)
	if !ok {
		return
	}
	if evt.Sender == tempAdmin && evt.GetStateKey() == m.Client.UserID.String() && content.Membership == event.MembershipInvite {
		m.Client.JoinRoomByID(ctx, evt.RoomID)
		m.Client.State(ctx, evt.RoomID)
	}
}

func (m *Meowlnir) LoadBanList(ctx context.Context, roomID id.RoomID) (*policylist.Room, error) {
	state, err := m.Client.State(ctx, roomID)
	if err != nil {
		return nil, fmt.Errorf("failed to get room state: %w", err)
	}
	m.PolicyStore.Add(roomID, state)
	return nil, nil
}

func (m *Meowlnir) HandleCommand(ctx context.Context, evt *event.Event) {
	if evt.Sender != tempAdmin {
		return
	}
	m.Client.State(ctx, evt.RoomID)
	fields := strings.Fields(evt.Content.AsMessage().Body)
	cmd := fields[0]
	args := fields[1:]
	switch strings.ToLower(cmd) {
	case "!join":
		m.Client.JoinRoomByID(ctx, id.RoomID(args[0]))
	case "!load":
		_, err := m.LoadBanList(ctx, id.RoomID(args[0]))
		if err != nil {
			m.Client.SendNotice(ctx, evt.RoomID, fmt.Sprintf("Failed to load ban list: %v", err))
		} else {
			m.Client.SendNotice(ctx, evt.RoomID, "Ban list loaded")
		}
	case "!match":
		match := m.PolicyStore.MatchUser(nil, id.UserID(args[0]))
		if match != nil {
			m.Client.SendNotice(ctx, evt.RoomID, fmt.Sprintf("Matched: %s set recommendation %s for %s at %s: %s", match.RawEvent.Sender, match.Recommendation, match.Entity, time.UnixMilli(match.RawEvent.Timestamp), match.Reason))
		} else {
			m.Client.SendNotice(ctx, evt.RoomID, "No match")
		}
	}
}
