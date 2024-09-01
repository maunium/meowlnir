package database

import (
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type TakenAction struct {
	PolicyList id.RoomID
	RuleEntity string
	TargetUser id.UserID
	Action     event.PolicyRecommendation
}
