package policylist

import (
	"go.mau.fi/util/glob"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Policy represents a single moderation policy event with the relevant data parsed out.
type Policy struct {
	*event.ModPolicyContent
	Pattern    glob.Glob
	EntityHash *[hashSize]byte

	EntityType EntityType
	RoomID     id.RoomID
	StateKey   string
	Sender     id.UserID
	Type       event.Type
	Timestamp  int64
	ID         id.EventID
	Ignored    bool
}

// Match represent a list of policies that matched a specific entity.
type Match []*Policy

type Recommendations struct {
	BanOrUnban *Policy
}

// Recommendations aggregates the recommendations in the match.
func (m Match) Recommendations() (output Recommendations) {
	for _, policy := range m {
		switch policy.Recommendation {
		case event.PolicyRecommendationBan, event.PolicyRecommendationUnban:
			if output.BanOrUnban == nil {
				output.BanOrUnban = policy
			}
		}
	}
	return
}
