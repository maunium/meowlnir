package policyeval

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policylist"
)

type PolicyEvaluator struct {
	Client *mautrix.Client
	Store  *policylist.Store

	Subscriptions  []id.RoomID
	ProtectedRooms []id.RoomID
	users          map[id.UserID][]id.RoomID
	usersLock      sync.RWMutex
}

func NewPolicyEvaluator(client *mautrix.Client, store *policylist.Store) *PolicyEvaluator {
	return &PolicyEvaluator{
		Client: client,
		Store:  store,
		users:  make(map[id.UserID][]id.RoomID),
	}
}

func (pe *PolicyEvaluator) Subscribe(ctx context.Context, roomID id.RoomID) error {
	if slices.Contains(pe.Subscriptions, roomID) {
		return nil
	}
	if !pe.Store.Contains(roomID) {
		state, err := pe.Client.State(ctx, roomID)
		if err != nil {
			return fmt.Errorf("failed to get room state: %w", err)
		}
		pe.Store.Add(roomID, state)
	}
	pe.Subscriptions = append(pe.Subscriptions, roomID)
	return nil
}

func (pe *PolicyEvaluator) Protect(ctx context.Context, roomID id.RoomID) error {
	members, err := pe.Client.Members(ctx, roomID)
	if err != nil {
		return fmt.Errorf("failed to get room members: %w", err)
	}
	pe.ProtectedRooms = append(pe.ProtectedRooms, roomID)
	start := time.Now()
	for _, evt := range members.Chunk {
		pe.HandleMember(ctx, evt)
	}
	zerolog.Ctx(ctx).Debug().Stringer("duration", time.Since(start)).Msg("Processed room members for protection")
	return nil
}

func (pe *PolicyEvaluator) updateUser(userID id.UserID, roomID id.RoomID, add bool) {
	pe.usersLock.Lock()
	defer pe.usersLock.Unlock()
	if add {
		if !slices.Contains(pe.users[userID], roomID) {
			pe.users[userID] = append(pe.users[userID], roomID)
		}
	} else if idx := slices.Index(pe.users[userID], roomID); idx >= 0 {
		deleted := slices.Delete(pe.users[userID], idx, idx+1)
		if len(deleted) == 0 {
			delete(pe.users, userID)
		} else {
			pe.users[userID] = deleted
		}
	}
}

func (pe *PolicyEvaluator) HandlePolicyListChange(ctx context.Context, added, removed *policylist.Policy) {
	zerolog.Ctx(ctx).Info().
		Any("added", added).
		Any("removed", removed).
		Msg("Policy list change")
}

func (pe *PolicyEvaluator) HandleMember(ctx context.Context, evt *event.Event) {
	if !slices.Contains(pe.ProtectedRooms, evt.RoomID) {
		return
	}
	switch evt.Content.AsMember().Membership {
	case event.MembershipJoin, event.MembershipInvite, event.MembershipKnock:
		pe.updateUser(id.UserID(evt.GetStateKey()), evt.RoomID, true)
		policy := pe.Store.MatchUser(pe.Subscriptions, id.UserID(evt.GetStateKey()))
		if policy != nil {
			zerolog.Ctx(ctx).Info().
				Str("user_id", evt.GetStateKey()).
				Any("policy", policy).
				Msg("Matched user in membership event")
		}
	case event.MembershipLeave, event.MembershipBan:
		pe.updateUser(id.UserID(evt.GetStateKey()), evt.RoomID, false)
	}
}
