package util

import (
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type EventPDU struct {
	AuthEvents []id.EventID `json:"auth_events"`
	Content    *event.Event `json:"content"`
	Depth      int64        `json:"depth"`
	Hashes     struct {
		Sha256 string `json:"sha256"`
	} `json:"hashes"`
	OriginServerTS int64                        `json:"origin_server_ts"`
	PrevEvents     []id.EventID                 `json:"prev_events"`
	RoomID         id.RoomID                    `json:"room_id"`
	Sender         id.UserID                    `json:"sender"`
	Signatures     map[string]map[string]string `json:"signatures"`
	StateKey       *string                      `json:"state_key"`
	Type           event.Type                   `json:"type"`
	Unsigned       *event.Unsigned              `json:"unsigned"`
}
