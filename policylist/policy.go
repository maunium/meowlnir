package policylist

import (
	"go.mau.fi/util/glob"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Policy represents a single moderation policy event with the relevant data parsed out.
type Policy struct {
	*event.ModPolicyContent
	Pattern glob.Glob

	RoomID    id.RoomID
	StateKey  string
	Sender    id.UserID
	Type      event.Type
	Timestamp int64
	ID        id.EventID
}

// Match represent a list of policies that matched a specific entity.
type Match []*Policy

type Recommendations struct {
	Ban   bool
	Unban bool
}

// Recommendations aggregates the recommendations in the match.
func (m Match) Recommendations() (output Recommendations) {
	for _, policy := range m {
		switch policy.Recommendation {
		case event.PolicyRecommendationBan:
			if !output.Unban {
				output.Ban = true
			}
		case event.PolicyRecommendationUnban:
			if !output.Ban {
				output.Unban = true
			}
		}
	}
	return
}
