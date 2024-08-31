package policylist

import (
	"sync"

	"golang.org/x/exp/maps"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Store is a collection of policy rooms that allows matching users, rooms, and servers
// against the policies of any subset of rooms in the store.
type Store struct {
	rooms     map[id.RoomID]*Room
	roomsLock sync.RWMutex
}

// NewStore creates a new policy list store.
func NewStore() *Store {
	return &Store{
		rooms: make(map[id.RoomID]*Room),
	}
}

// MatchUser finds the first matching policy for the given user ID in the given policy rooms.
// If no matches are found, nil is returned.
func (s *Store) MatchUser(listIDs []id.RoomID, userID id.UserID) *Policy {
	return s.match(listIDs, string(userID), (*Room).GetUserRules)
}

// MatchRoom finds the first matching policy for the given room ID in the given policy rooms.
// If no matches are found, nil is returned.
func (s *Store) MatchRoom(listIDs []id.RoomID, roomID id.RoomID) *Policy {
	return s.match(listIDs, string(roomID), (*Room).GetRoomRules)
}

// MatchServer finds the first matching policy for the given server name in the given policy rooms.
// If no matches are found, nil is returned.
func (s *Store) MatchServer(listIDs []id.RoomID, serverName string) *Policy {
	return s.match(listIDs, serverName, (*Room).GetServerRules)
}

// Update updates the store with the given policy event.
//
// The provided event will be ignored if it belongs to a room that is not tracked by this store,
// is not a moderation policy event, or is not a state event.
//
// If the event doesn't have the `entity` and `recommendation` fields set,
// it will be treated as removing the current policy.
//
// The added and removed/replaced policies (if any) are returned
func (s *Store) Update(evt *event.Event) (added, removed *Policy) {
	switch evt.Type {
	case event.StatePolicyUser, event.StateLegacyPolicyUser, event.StateUnstablePolicyUser,
		event.StatePolicyRoom, event.StateLegacyPolicyRoom, event.StateUnstablePolicyRoom,
		event.StatePolicyServer, event.StateLegacyPolicyServer, event.StateUnstablePolicyServer:
	default:
		return
	}
	s.roomsLock.RLock()
	list, ok := s.rooms[evt.RoomID]
	s.roomsLock.RUnlock()
	if !ok {
		return
	}
	return list.Update(evt)
}

// Add adds a room to the store with the given state.
//
// This will always replace the existing state for the given room, even if it already exists.
//
// To ensure the store doesn't contain partial state, the store is locked for the duration of the parsing.
func (s *Store) Add(roomID id.RoomID, state map[event.Type]map[string]*event.Event) {
	s.roomsLock.Lock()
	s.rooms[roomID] = NewRoom(roomID).ParseState(state)
	s.roomsLock.Unlock()
}

func (s *Store) match(listIDs []id.RoomID, entity string, listGetter func(*Room) *List) *Policy {
	if listIDs == nil {
		s.roomsLock.Lock()
		listIDs = maps.Keys(s.rooms)
		s.roomsLock.Unlock()
	}
	ruleLists := make([]*List, len(listIDs))
	for i, roomID := range listIDs {
		s.roomsLock.RLock()
		list, ok := s.rooms[roomID]
		s.roomsLock.RUnlock()
		if !ok {
			continue
		}
		rules := listGetter(list)
		if policy := rules.MatchLiteral(entity); policy != nil {
			return policy
		}
		ruleLists[i] = rules
	}
	for _, rules := range ruleLists {
		if policy := rules.MatchDynamic(entity); policy != nil {
			return policy
		}
	}
	return nil
}
