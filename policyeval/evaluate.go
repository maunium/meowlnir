package policyeval

import (
	"context"
	"iter"
	"maps"
	"slices"

	"github.com/rs/zerolog"
	"go.mau.fi/util/glob"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/database"
	"go.mau.fi/meowlnir/policylist"
)

func (pe *PolicyEvaluator) getAllUsers() []id.UserID {
	pe.protectedRoomsLock.RLock()
	defer pe.protectedRoomsLock.RUnlock()
	return slices.Collect(maps.Keys(pe.protectedRoomMembers))
}

func (pe *PolicyEvaluator) getUserIDFromHash(hash [32]byte) (id.UserID, bool) {
	pe.protectedRoomsLock.RLock()
	defer pe.protectedRoomsLock.RUnlock()
	userID, ok := pe.memberHashes[hash]
	return userID, ok
}

func (pe *PolicyEvaluator) findMatchingUsers(pattern glob.Glob, hash *[32]byte) iter.Seq[id.UserID] {
	return func(yield func(id.UserID) bool) {
		if hash != nil {
			userID, ok := pe.getUserIDFromHash(*hash)
			if ok {
				yield(userID)
			}
			return
		}
		exact, ok := pattern.(glob.ExactGlob)
		if ok {
			userID := id.UserID(exact)
			pe.protectedRoomsLock.RLock()
			defer pe.protectedRoomsLock.RUnlock()
			_, found := pe.protectedRoomMembers[userID]
			if found {
				yield(userID)
			}
			return
		}
		users := pe.getAllUsers()
		for _, userID := range users {
			if pattern.Match(string(userID)) {
				if !yield(userID) {
					return
				}
			}
		}
	}
}

func (pe *PolicyEvaluator) EvaluateAll(ctx context.Context) {
	pe.EvaluateAllMembers(ctx, pe.getAllUsers())
}

func (pe *PolicyEvaluator) EvaluateAllMembers(ctx context.Context, members []id.UserID) {
	for _, member := range members {
		pe.EvaluateUser(ctx, member, false)
	}
}

func (pe *PolicyEvaluator) EvaluateUser(ctx context.Context, userID id.UserID, isNewRule bool) {
	match := pe.Store.MatchUser(pe.GetWatchedLists(), userID)
	if match == nil {
		return
	}
	pe.ApplyPolicy(ctx, userID, match, isNewRule)
}

func (pe *PolicyEvaluator) EvaluateRemovedRule(ctx context.Context, policy *policylist.Policy) {
	if policy.Recommendation == event.PolicyRecommendationUnban {
		// When an unban rule is removed, evaluate all joined users against the removed rule
		// to see if they should be re-evaluated against all rules (and possibly banned)
		for userID := range pe.findMatchingUsers(policy.Pattern, policy.EntityHash) {
			pe.EvaluateUser(ctx, userID, false)
		}
	} else {
		// For ban rules, find users who were banned by the rule and re-evaluate them.
		reevalTargets, err := pe.DB.TakenAction.GetAllByRuleEntity(ctx, policy.RoomID, policy.EntityOrHash())
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Str("policy_entity", policy.EntityOrHash()).
				Msg("Failed to get actions taken for removed policy")
			pe.sendNotice(ctx, "Database error in EvaluateRemovedRule (GetAllByRuleEntity): %v", err)
			return
		}
		pe.ReevaluateActions(ctx, reevalTargets)
	}
}

func (pe *PolicyEvaluator) EvaluateAddedRule(ctx context.Context, policy *policylist.Policy) {
	for userID := range pe.findMatchingUsers(policy.Pattern, policy.EntityHash) {
		// Do a full evaluation to ensure new policies don't bypass existing higher priority policies
		pe.EvaluateUser(ctx, userID, true)
	}
}

func (pe *PolicyEvaluator) ReevaluateAffectedByLists(ctx context.Context, policyLists []id.RoomID) {
	var reevalTargets []*database.TakenAction
	for _, list := range policyLists {
		targets, err := pe.DB.TakenAction.GetAllByPolicyList(ctx, list)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Stringer("policy_list_id", list).
				Msg("Failed to get actions taken from policy list")
			pe.sendNotice(ctx, "Database error in ReevaluateAffectedByLists (GetAllByPolicyList): %v", err)
			continue
		}
		if reevalTargets == nil {
			reevalTargets = targets
		} else {
			reevalTargets = append(reevalTargets, targets...)
		}
	}
	pe.ReevaluateActions(ctx, reevalTargets)
}

func (pe *PolicyEvaluator) ReevaluateActions(ctx context.Context, actions []*database.TakenAction) {

}
