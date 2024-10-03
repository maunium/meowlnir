package policylist

import (
	"go.mau.fi/util/glob"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type typeStateKeyTuple struct {
	Type     event.Type
	StateKey string
}

// Room represents a single moderation policy room and all the policies inside it.
type Room struct {
	RoomID      id.RoomID
	UserRules   *List
	RoomRules   *List
	ServerRules *List
	byEventID   map[id.EventID]typeStateKeyTuple
}

// NewRoom creates a new store for a single policy room.
func NewRoom(roomID id.RoomID) *Room {
	return &Room{
		RoomID:      roomID,
		UserRules:   NewList(roomID, "user"),
		RoomRules:   NewList(roomID, "room"),
		ServerRules: NewList(roomID, "server"),
		byEventID:   make(map[id.EventID]typeStateKeyTuple),
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

type EntityType string

func (et EntityType) EventType() event.Type {
	switch et {
	case EntityTypeUser:
		return event.StatePolicyUser
	case EntityTypeRoom:
		return event.StatePolicyRoom
	case EntityTypeServer:
		return event.StatePolicyServer
	}
	return event.Type{}
}

const (
	EntityTypeUser   EntityType = "user"
	EntityTypeRoom   EntityType = "room"
	EntityTypeServer EntityType = "server"
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
		added, removed = r.updatePolicyList(evt, EntityTypeUser, r.UserRules)
	case event.StatePolicyRoom, event.StateLegacyPolicyRoom, event.StateUnstablePolicyRoom:
		added, removed = r.updatePolicyList(evt, EntityTypeRoom, r.RoomRules)
	case event.StatePolicyServer, event.StateLegacyPolicyServer, event.StateUnstablePolicyServer:
		added, removed = r.updatePolicyList(evt, EntityTypeServer, r.ServerRules)
	case event.EventRedaction:
		redacts := evt.Redacts
		if redacts == "" {
			redacts = evt.Content.AsRedaction().Redacts
		}
		target, ok := r.byEventID[redacts]
		if ok {
			switch target.Type {
			case event.StatePolicyUser, event.StateLegacyPolicyUser, event.StateUnstablePolicyUser:
				removed = r.UserRules.Remove(target.Type, target.StateKey)
			case event.StatePolicyRoom, event.StateLegacyPolicyRoom, event.StateUnstablePolicyRoom:
				removed = r.RoomRules.Remove(target.Type, target.StateKey)
			case event.StatePolicyServer, event.StateLegacyPolicyServer, event.StateUnstablePolicyServer:
				removed = r.ServerRules.Remove(target.Type, target.StateKey)
			}
		}
	}
	return
}

// ParseState updates the state of this object with the given state events.
func (r *Room) ParseState(state map[event.Type]map[string]*event.Event) *Room {
	userPolicies := mergeUnstableEvents(state[event.StatePolicyUser], state[event.StateLegacyPolicyUser], state[event.StateUnstablePolicyUser])
	roomPolicies := mergeUnstableEvents(state[event.StatePolicyRoom], state[event.StateLegacyPolicyRoom], state[event.StateUnstablePolicyRoom])
	serverPolicies := mergeUnstableEvents(state[event.StatePolicyServer], state[event.StateLegacyPolicyServer], state[event.StateUnstablePolicyServer])
	r.massUpdatePolicyList(userPolicies, EntityTypeUser, r.UserRules)
	r.massUpdatePolicyList(roomPolicies, EntityTypeRoom, r.RoomRules)
	r.massUpdatePolicyList(serverPolicies, EntityTypeServer, r.ServerRules)
	return r
}

func mergeUnstableEvents(into map[string]*event.Event, sources ...map[string]*event.Event) (output map[string]*event.Event) {
	output = into
	if output == nil {
		output = make(map[string]*event.Event)
	}
	for _, source := range sources {
		for key, evt := range source {
			if _, ok := output[key]; !ok {
				output[key] = evt
			}
		}
	}
	return output
}

func (r *Room) massUpdatePolicyList(input map[string]*event.Event, entityType EntityType, rules *List) {
	for _, evt := range input {
		r.updatePolicyList(evt, entityType, rules)
	}
}

var HackyRuleFilter []string

func (r *Room) updatePolicyList(evt *event.Event, entityType EntityType, rules *List) (added, removed *Policy) {
	content, ok := evt.Content.Parsed.(*event.ModPolicyContent)
	if !ok || evt.StateKey == nil {
		return
	}
	r.byEventID[evt.ID] = typeStateKeyTuple{Type: evt.Type, StateKey: *evt.StateKey}
	if content.Entity == "" || content.Recommendation == "" {
		removed = rules.Remove(evt.Type, *evt.StateKey)
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
	if added.Recommendation == event.PolicyRecommendationBan {
		for _, entry := range HackyRuleFilter {
			if added.Pattern.Match(entry) {
				added.Ignored = true
			}
		}
	}
	var wasAdded bool
	removed, wasAdded = rules.Add(added)
	if !wasAdded {
		added = nil
	}
	return
}
