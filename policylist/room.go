package policylist

import (
	"go.mau.fi/util/glob"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Room represents a single moderation policy room and all the policies inside it.
type Room struct {
	RoomID      id.RoomID
	UserRules   *List
	RoomRules   *List
	ServerRules *List
}

// NewRoom creates a new store for a single policy room.
func NewRoom(roomID id.RoomID) *Room {
	return &Room{
		RoomID:      roomID,
		UserRules:   NewList(roomID, "user"),
		RoomRules:   NewList(roomID, "room"),
		ServerRules: NewList(roomID, "server"),
	}
}

func (r *Room) GetUserRules() *List {
	return r.UserRules
}

func (r *Room) GetRoomRules() *List {
	return r.RoomRules
}

func (r *Room) GetServerRules() *List {
	return r.ServerRules
}

const (
	entityTypeUser   = "user"
	entityTypeRoom   = "room"
	entityTypeServer = "server"
)

// Update updates the state of this object with the given policy event.
//
// It returns the added and removed/replaced policies, if any.
func (r *Room) Update(evt *event.Event) (added, removed *Policy) {
	if r == nil || evt.RoomID != r.RoomID {
		return
	}
	switch evt.Type {
	case event.StatePolicyUser, event.StateLegacyPolicyUser, event.StateUnstablePolicyUser:
		added, removed = updatePolicyList(evt, entityTypeUser, r.UserRules)
	case event.StatePolicyRoom, event.StateLegacyPolicyRoom, event.StateUnstablePolicyRoom:
		added, removed = updatePolicyList(evt, entityTypeRoom, r.RoomRules)
	case event.StatePolicyServer, event.StateLegacyPolicyServer, event.StateUnstablePolicyServer:
		added, removed = updatePolicyList(evt, entityTypeServer, r.ServerRules)
	}
	return
}

// ParseState updates the state of this object with the given state events.
func (r *Room) ParseState(state map[event.Type]map[string]*event.Event) *Room {
	mergeUnstableEvents(state[event.StatePolicyUser], state[event.StateLegacyPolicyUser], state[event.StateUnstablePolicyUser])
	mergeUnstableEvents(state[event.StatePolicyRoom], state[event.StateLegacyPolicyRoom], state[event.StateUnstablePolicyRoom])
	mergeUnstableEvents(state[event.StatePolicyServer], state[event.StateLegacyPolicyServer], state[event.StateUnstablePolicyServer])
	massUpdatePolicyList(state[event.StatePolicyUser], entityTypeUser, r.UserRules)
	massUpdatePolicyList(state[event.StatePolicyRoom], entityTypeRoom, r.RoomRules)
	massUpdatePolicyList(state[event.StatePolicyServer], entityTypeServer, r.ServerRules)
	return r
}

func mergeUnstableEvents(into map[string]*event.Event, sources ...map[string]*event.Event) {
	for _, source := range sources {
		for key, evt := range source {
			if _, ok := into[key]; !ok {
				into[key] = evt
			}
		}
	}
}

func massUpdatePolicyList(input map[string]*event.Event, entityType string, rules *List) {
	for _, evt := range input {
		updatePolicyList(evt, entityType, rules)
	}
}

func updatePolicyList(evt *event.Event, entityType string, rules *List) (added, removed *Policy) {
	content, ok := evt.Content.Parsed.(*event.ModPolicyContent)
	if !ok || evt.StateKey == nil {
		return
	} else if content.Entity == "" || content.Recommendation == "" {
		rules.Remove(evt.Type, *evt.StateKey)
		return
	}
	if content.Recommendation == event.PolicyRecommendationUnstableBan {
		content.Recommendation = event.PolicyRecommendationBan
	}
	added = &Policy{
		ModPolicyContent: content,
		Pattern:          glob.Compile(content.Entity),

		EntityType: entityType,
		RoomID:     evt.RoomID,
		StateKey:   *evt.StateKey,
		Sender:     evt.Sender,
		Type:       evt.Type,
		Timestamp:  evt.Timestamp,
		ID:         evt.ID,
	}
	var wasAdded bool
	removed, wasAdded = rules.Add(added)
	if !wasAdded {
		added = nil
	}
	return
}
