package policylist

import (
	"go.mau.fi/util/glob"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/util"
)

// Policy represents a single moderation policy event with the relevant data parsed out.
type Policy struct {
	*event.ModPolicyContent
	Pattern    glob.Glob            `json:"-"`
	EntityHash *[util.HashSize]byte `json:"-"`

	EntityType EntityType `json:"entity_type"`
	RoomID     id.RoomID  `json:"room_id"`
	StateKey   string     `json:"state_key"`
	Sender     id.UserID  `json:"sender"`
	Type       event.Type `json:"type"`
	Timestamp  int64      `json:"timestamp"`
	ID         id.EventID `json:"event_id"`
	Ignored    bool       `json:"ignored"`
}

// Match represent a list of policies that matched a specific entity.
type Match []*Policy

type Recommendations struct {
	BanOrUnban *Policy
}

func (r Recommendations) String() string {
	if r.BanOrUnban != nil {
		return string(r.BanOrUnban.Recommendation)
	}
	return ""
}

// Recommendations aggregates the recommendations in the match.
func (m Match) Recommendations() (output Recommendations) {
	for _, policy := range m {
		switch policy.Recommendation {
		case event.PolicyRecommendationBan, event.PolicyRecommendationUnban, event.PolicyRecommendationUnstableTakedown:
			if output.BanOrUnban == nil {
				output.BanOrUnban = policy
			}
		}
	}
	return
}
