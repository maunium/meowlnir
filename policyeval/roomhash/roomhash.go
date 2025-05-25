package roomhash

import (
	"sync"

	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/util"
)

type Map struct {
	hashToRoomID map[[32]byte]id.RoomID
	lock         sync.RWMutex
}

func NewMap() *Map {
	return &Map{
		hashToRoomID: make(map[[32]byte]id.RoomID),
	}
}

func (m *Map) Put(roomID id.RoomID) bool {
	hash := util.SHA256String(roomID)
	m.lock.Lock()
	_, exists := m.hashToRoomID[hash]
	if !exists {
		m.hashToRoomID[hash] = roomID
	}
	m.lock.Unlock()
	return !exists
}

func (m *Map) Get(hash [32]byte) id.RoomID {
	m.lock.RLock()
	roomID := m.hashToRoomID[hash]
	m.lock.RUnlock()
	return roomID
}

func (m *Map) Has(roomID id.RoomID) bool {
	hash := util.SHA256String(roomID)
	m.lock.RLock()
	_, exists := m.hashToRoomID[hash]
	m.lock.RUnlock()
	return exists
}
