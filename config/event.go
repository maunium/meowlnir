package config

import (
	"reflect"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var (
	StateWatchedLists   = event.Type{Type: "fi.mau.meowlnir.watched_lists", Class: event.StateEventType}
	StateProtectedRooms = event.Type{Type: "fi.mau.meowlnir.protected_rooms", Class: event.StateEventType}
)

type WatchedPolicyList struct {
	RoomID       id.RoomID `json:"room_id"`
	Name         string    `json:"name"`
	Shortcode    string    `json:"shortcode"`
	DontApply    bool      `json:"dont_apply"`
	DontApplyACL bool      `json:"dont_apply_acl"`
	AutoUnban    bool      `json:"auto_unban"`
}

type WatchedListsEventContent struct {
	Lists []WatchedPolicyList `json:"lists"`
}

type ProtectedRoomsEventContent struct {
	Rooms []id.RoomID `json:"rooms"`
}

func init() {
	event.TypeMap[StateWatchedLists] = reflect.TypeOf(WatchedListsEventContent{})
	event.TypeMap[StateProtectedRooms] = reflect.TypeOf(ProtectedRoomsEventContent{})
}
