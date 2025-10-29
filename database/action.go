package database

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exslices"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

const (
	getTakenActionBaseQuery = `
		SELECT target_user, in_room_id, action_type, policy_list, rule_entity, action, taken_at
		FROM taken_action
	`
	getTakenActionsByPolicyListQuery = getTakenActionBaseQuery + `WHERE policy_list=$1 AND in_room_id=ANY($2)`
	getTakenActionsByRuleEntityQuery = getTakenActionBaseQuery + `WHERE policy_list=$1 AND rule_entity=$2 AND in_room_id=ANY($3)`
	getTakenActionByTargetUserQuery  = getTakenActionBaseQuery + `WHERE target_user=$1 AND action_type=$2 AND in_room_id=ANY($3)`
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

func (taq *TakenActionQuery) queryManyWithRoomList(ctx context.Context, roomIDs []id.RoomID, query string, args ...any) ([]*TakenAction, error) {
	switch taq.GetDB().Dialect {
	case dbutil.SQLite:
		staticArgCount := len(args)
		postgresAny := fmt.Sprintf("in_room_id=ANY($%d)", staticArgCount+1)
		sqlitePlaceholders := make([]string, len(roomIDs))
		for i := range roomIDs {
			sqlitePlaceholders[i] = fmt.Sprintf("$%d", staticArgCount+1+i)
			args = append(args, roomIDs[i])
		}
		sqliteAny := fmt.Sprintf("in_room_id IN (%s)", strings.Join(sqlitePlaceholders, ","))
		newQuery := strings.Replace(query, postgresAny, sqliteAny, 1)
		if newQuery == query {
			return nil, fmt.Errorf("replacement %q -> %q failed in %q", postgresAny, sqliteAny, query)
		}
		query = newQuery
	case dbutil.Postgres:
		args = append(args, pq.Array(exslices.CastToString[string](roomIDs)))
	default:
		return nil, fmt.Errorf("unsupported dialect: %s", taq.GetDB().Dialect)
	}
	return taq.QueryMany(ctx, query, args...)
}

func (taq *TakenActionQuery) GetAllByPolicyList(ctx context.Context, policyList id.RoomID, inRooms []id.RoomID) ([]*TakenAction, error) {
	return taq.queryManyWithRoomList(ctx, inRooms, getTakenActionsByPolicyListQuery, policyList)
}

func (taq *TakenActionQuery) GetAllByRuleEntity(ctx context.Context, policyList id.RoomID, ruleEntity string, inRooms []id.RoomID) ([]*TakenAction, error) {
	return taq.queryManyWithRoomList(ctx, inRooms, getTakenActionsByRuleEntityQuery, policyList, ruleEntity)
}

func (taq *TakenActionQuery) GetAllByTargetUser(ctx context.Context, userID id.UserID, actionType TakenActionType, inRooms []id.RoomID) ([]*TakenAction, error) {
	return taq.queryManyWithRoomList(ctx, inRooms, getTakenActionByTargetUserQuery, userID, actionType)
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
