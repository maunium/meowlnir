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
	RoomID       id.RoomID `json:"room_id" yaml:"room_id"`
	Name         string    `json:"name" yaml:"name"`
	Shortcode    string    `json:"shortcode" yaml:"shortcode"`
	DontApply    bool      `json:"dont_apply" yaml:"dont_apply"`
	DontApplyACL bool      `json:"dont_apply_acl" yaml:"dont_apply_acl"`
	AutoUnban    bool      `json:"auto_unban" yaml:"auto_unban"`
	AutoSuspend  bool      `json:"auto_suspend" yaml:"auto_suspend"`

	DontNotifyOnChange bool `json:"dont_notify_on_change" yaml:"dont_notify_on_change"`

	InRoom bool `json:"-" yaml:"-"`
}

type WatchedListsEventContent struct {
	Lists []WatchedPolicyList `json:"lists"`
}

type ProtectedRoomsEventContent struct {
	Rooms       []id.RoomID               `json:"rooms"`
	Protections map[string]map[string]any `json:"protections,omitempty"`

	// TODO make this less hacky
	SkipACL []id.RoomID `json:"skip_acl"`
}

func init() {
	event.TypeMap[StateWatchedLists] = reflect.TypeOf(WatchedListsEventContent{})
	event.TypeMap[StateProtectedRooms] = reflect.TypeOf(ProtectedRoomsEventContent{})
}
