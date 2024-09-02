package policyeval

import (
	"context"
	"maps"
	"slices"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policylist"
)

func (pe *PolicyEvaluator) EvaluateAll(ctx context.Context) {
	pe.usersLock.RLock()
	users := slices.Collect(maps.Keys(pe.users))
	pe.usersLock.RUnlock()
	pe.EvaluateAllMembers(ctx, users)
}

func (pe *PolicyEvaluator) EvaluateAllMembers(ctx context.Context, members []id.UserID) {
	for _, member := range members {
		pe.EvaluateNewMember(ctx, member)
	}
}

func (pe *PolicyEvaluator) EvaluateNewMember(ctx context.Context, userID id.UserID) {
	match := pe.Store.MatchUser(pe.GetWatchedLists(), userID)
	if match == nil {
		return
	}
	zerolog.Ctx(ctx).Info().
		Stringer("user_id", userID).
		Any("recommendation", match.Recommendations()).
		Any("matches", match).
		Msg("Matched user in membership event")
}

func (pe *PolicyEvaluator) EvaluateRemovedRule(ctx context.Context, policy *policylist.Policy) {
	// TODO
}

func (pe *PolicyEvaluator) EvaluateAddedRule(ctx context.Context, policy *policylist.Policy) {
	// TODO
}
