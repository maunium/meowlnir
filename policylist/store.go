package policylist

import (
	"maps"
	"regexp"
	"slices"
	"sync"

	"go.mau.fi/util/glob"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/util"
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

// MatchUser finds all matching policies for the given user ID in the given policy rooms.
func (s *Store) MatchUser(listIDs []id.RoomID, userID id.UserID) Match {
	return s.match(listIDs, string(userID), (*Room).GetUserRules)
}

// MatchRoom finds all matching policies for the given room ID in the given policy rooms.
// If no matches are found, nil is returned.
func (s *Store) MatchRoom(listIDs []id.RoomID, roomID id.RoomID) Match {
	return s.match(listIDs, string(roomID), (*Room).GetRoomRules)
}

var portRegex = regexp.MustCompile(`:\d+$`)
var ipRegex = regexp.MustCompile(`^(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:\[[0-9a-fA-F:.]+\])$`)
var fakeBanForIPLiterals = &Policy{
	ModPolicyContent: &event.ModPolicyContent{
		Recommendation: event.PolicyRecommendationBan,
		Entity:         "IP literal",
		Reason:         "IP literals are not allowed",
	},
	EntityType: EntityTypeServer,
}

func CleanupServerNameForMatch(serverName string) string {
	return portRegex.ReplaceAllString(serverName, "")
}

func IsIPLiteral(serverName string) bool {
	return ipRegex.MatchString(serverName)
}

// MatchServer finds all matching policies for the given server name in the given policy rooms.
func (s *Store) MatchServer(listIDs []id.RoomID, serverName string) Match {
	serverName = CleanupServerNameForMatch(serverName)
	if IsIPLiteral(serverName) {
		return Match{fakeBanForIPLiterals}
	}
	return s.match(listIDs, serverName, (*Room).GetServerRules)
}

func (s *Store) ListServerRules(listIDs []id.RoomID) map[string]*Policy {
	return s.compileList(listIDs, (*Room).GetServerRules)
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
		event.StatePolicyServer, event.StateLegacyPolicyServer, event.StateUnstablePolicyServer,
		event.EventRedaction:
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

func (s *Store) Contains(roomID id.RoomID) bool {
	s.roomsLock.RLock()
	_, ok := s.rooms[roomID]
	s.roomsLock.RUnlock()
	return ok
}

func (s *Store) match(listIDs []id.RoomID, entity string, listGetter func(*Room) *List) (output Match) {
	if listIDs == nil {
		s.roomsLock.Lock()
		listIDs = slices.Collect(maps.Keys(s.rooms))
		s.roomsLock.Unlock()
	}
	for _, roomID := range listIDs {
		s.roomsLock.RLock()
		list, ok := s.rooms[roomID]
		s.roomsLock.RUnlock()
		if !ok {
			continue
		}
		rules := listGetter(list)
		output = append(output, rules.Match(entity)...)
	}
	return
}

func (s *Store) matchExactFunc(listIDs []id.RoomID, entityType EntityType, fn func(*List) Match) (output Match) {
	if listIDs == nil {
		s.roomsLock.Lock()
		listIDs = slices.Collect(maps.Keys(s.rooms))
		s.roomsLock.Unlock()
	}
	for _, roomID := range listIDs {
		s.roomsLock.RLock()
		list, ok := s.rooms[roomID]
		s.roomsLock.RUnlock()
		if !ok {
			continue
		}
		var rules *List
		switch entityType {
		case EntityTypeUser:
			rules = list.GetUserRules()
		case EntityTypeRoom:
			rules = list.GetRoomRules()
		case EntityTypeServer:
			rules = list.GetServerRules()
		}
		output = append(output, fn(rules)...)
	}
	return
}

func (s *Store) MatchExact(listIDs []id.RoomID, entityType EntityType, entity string) (output Match) {
	return s.matchExactFunc(listIDs, entityType, func(list *List) Match {
		return list.MatchExact(entity)
	})
}

func (s *Store) MatchHash(listIDs []id.RoomID, entityType EntityType, entity [util.HashSize]byte) (output Match) {
	return s.matchExactFunc(listIDs, entityType, func(list *List) Match {
		return list.MatchHash(entity)
	})
}

func (s *Store) Search(listIDs []id.RoomID, entity string) (output Match) {
	if listIDs == nil {
		s.roomsLock.Lock()
		listIDs = slices.Collect(maps.Keys(s.rooms))
		s.roomsLock.Unlock()
	}
	entityGlob := glob.Compile(entity)
	for _, roomID := range listIDs {
		s.roomsLock.RLock()
		list, ok := s.rooms[roomID]
		s.roomsLock.RUnlock()
		if !ok {
			continue
		}
		output = append(output, list.GetUserRules().Search(entity, entityGlob)...)
		output = append(output, list.GetRoomRules().Search(entity, entityGlob)...)
		output = append(output, list.GetServerRules().Search(entity, entityGlob)...)
	}
	return
}

func (s *Store) compileList(listIDs []id.RoomID, listGetter func(*Room) *List) (output map[string]*Policy) {
	output = make(map[string]*Policy)
	// Iterate the list backwards so that entries in higher priority lists overwrite lower priority ones
	for _, roomID := range slices.Backward(listIDs) {
		s.roomsLock.RLock()
		list, ok := s.rooms[roomID]
		s.roomsLock.RUnlock()
		if !ok {
			continue
		}
		rules := listGetter(list)
		rules.lock.RLock()
		for _, policy := range rules.byEntity {
			output[policy.Entity] = policy.Policy
		}
		rules.lock.RUnlock()
	}
	return
}
