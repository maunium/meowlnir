package config

import (
	"reflect"
	"time"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

var (
	StateWatchedLists        = event.Type{Type: "fi.mau.meowlnir.watched_lists", Class: event.StateEventType}
	StateProtectedRooms      = event.Type{Type: "fi.mau.meowlnir.protected_rooms", Class: event.StateEventType}
	StatePassiveFailover     = event.Type{Type: "fi.mau.meowlnir.passive_failover", Class: event.StateEventType}
	EventPassiveFailoverPing = event.Type{Type: "fi.mau.meowlnir.passive_failover.ping", Class: event.MessageEventType}
	EventPassiveFailoverPong = event.Type{Type: "fi.mau.meowlnir.passive_failover.pong", Class: event.MessageEventType}
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
	Rooms []id.RoomID `json:"rooms"`

	// TODO make this less hacky
	SkipACL []id.RoomID `json:"skip_acl"`
}

type PassiveFailoverContent struct {
	RoomID   id.RoomID     `json:"room_id"`
	Interval time.Duration `json:"interval"`
	Timeout  time.Duration `json:"timeout"`
	Primary  id.UserID     `json:"primary"`
}

type PassiveFailoverPing struct {
	Target id.UserID `json:"target"`
}

type PassiveFailoverPong struct {
	RelatesTo event.RelatesTo `json:"m.in_relation_to"`
}

func init() {
	event.TypeMap[StateWatchedLists] = reflect.TypeOf(WatchedListsEventContent{})
	event.TypeMap[StateProtectedRooms] = reflect.TypeOf(ProtectedRoomsEventContent{})
	event.TypeMap[StatePassiveFailover] = reflect.TypeOf(PassiveFailoverContent{})
	event.TypeMap[EventPassiveFailoverPing] = reflect.TypeOf(PassiveFailoverPing{})
	event.TypeMap[EventPassiveFailoverPong] = reflect.TypeOf(PassiveFailoverPong{})
}
