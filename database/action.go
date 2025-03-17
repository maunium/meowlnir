package database

import (
	"context"
	"time"

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	getTakenActionBaseQuery = `
		SELECT target_user, in_room_id, action_type, policy_list, rule_entity, action, taken_at
		FROM taken_action
	`
	getTakenActionsByPolicyListQuery = getTakenActionBaseQuery + `WHERE policy_list=$1`
	getTakenActionsByRuleEntityQuery = getTakenActionBaseQuery + `WHERE policy_list=$1 AND rule_entity=$2`
	getTakenActionByTargetUserQuery  = getTakenActionBaseQuery + `WHERE target_user=$1 AND action_type=$2`
	insertTakenActionQuery           = `
		INSERT INTO taken_action (target_user, in_room_id, action_type, policy_list, rule_entity, action, taken_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (target_user, in_room_id, action_type) DO UPDATE
			SET policy_list=excluded.policy_list, rule_entity=excluded.rule_entity, action=excluded.action, taken_at=excluded.taken_at
	`
	deleteTakenActionQuery = `DELETE FROM taken_action WHERE target_user=$1 AND in_room_id=$2 AND action_type=$3`
)

type TakenActionQuery struct {
	*dbutil.QueryHelper[*TakenAction]
}

func (taq *TakenActionQuery) Delete(ctx context.Context, targetUser id.UserID, inRoomID id.RoomID, actionType TakenActionType) error {
	return taq.Exec(ctx, deleteTakenActionQuery, targetUser, inRoomID, actionType)
}

func (taq *TakenActionQuery) Put(ctx context.Context, ta *TakenAction) error {
	return taq.Exec(ctx, insertTakenActionQuery, ta.sqlVariables()...)
}

func (taq *TakenActionQuery) GetAllByPolicyList(ctx context.Context, policyList id.RoomID) ([]*TakenAction, error) {
	return taq.QueryMany(ctx, getTakenActionsByPolicyListQuery, policyList)
}

func (taq *TakenActionQuery) GetAllByRuleEntity(ctx context.Context, policyList id.RoomID, ruleEntity string) ([]*TakenAction, error) {
	return taq.QueryMany(ctx, getTakenActionsByRuleEntityQuery, policyList, ruleEntity)
}

func (taq *TakenActionQuery) GetAllByTargetUser(ctx context.Context, userID id.UserID, actionType TakenActionType) ([]*TakenAction, error) {
	return taq.QueryMany(ctx, getTakenActionByTargetUserQuery, userID, actionType)
}

type TakenActionType string

const (
	TakenActionTypeBanOrUnban TakenActionType = "ban_or_unban"
)

type TakenAction struct {
	TargetUser id.UserID
	InRoomID   id.RoomID
	ActionType TakenActionType
	PolicyList id.RoomID
	RuleEntity string
	Action     event.PolicyRecommendation
	TakenAt    time.Time
}

func (t *TakenAction) sqlVariables() []any {
	return []any{t.TargetUser, t.InRoomID, t.ActionType, t.PolicyList, t.RuleEntity, t.Action, t.TakenAt.UnixMilli()}
}

func (t *TakenAction) Scan(row dbutil.Scannable) (*TakenAction, error) {
	var takenAt int64
	err := row.Scan(&t.TargetUser, &t.InRoomID, &t.ActionType, &t.PolicyList, &t.RuleEntity, &t.Action, &takenAt)
	if err != nil {
		return nil, err
	}
	t.TakenAt = time.UnixMilli(takenAt)
	return t, nil
}
