package policyeval

import (
	"context"
	"fmt"
	"slices"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/config"
)

func (pe *PolicyEvaluator) IsProtectedRoom(roomID id.RoomID) bool {
	pe.usersLock.RLock()
	_, protected := pe.protectedRooms[roomID]
	pe.usersLock.RUnlock()
	return protected
}

func (pe *PolicyEvaluator) handleProtectedRooms(ctx context.Context, evt *event.Event, isInitial bool) (out []string) {
	content, ok := evt.Content.Parsed.(*config.ProtectedRoomsEventContent)
	if !ok {
		return []string{"* Failed to parse protected rooms event"}
	}
	for _, roomID := range content.Rooms {
		if pe.IsProtectedRoom(roomID) {
			continue
		}
		members, err := pe.Client.Members(ctx, roomID)
		if err != nil {
			out = append(out, fmt.Sprintf("* Failed to get room members for [%s](%s): %v", roomID, roomID.URI().MatrixToURL(), err))
			continue
		}
		pe.markAsProtectedRoom(roomID, members.Chunk)
		if !isInitial {
			memberUserIDs := make([]id.UserID, len(members.Chunk))
			for i, member := range members.Chunk {
				memberUserIDs[i] = id.UserID(member.GetStateKey())
			}
			pe.EvaluateAllMembers(ctx, memberUserIDs)
		}
	}
	return
}

func (pe *PolicyEvaluator) markAsProtectedRoom(roomID id.RoomID, evts []*event.Event) {
	pe.usersLock.Lock()
	defer pe.usersLock.Unlock()
	pe.protectedRooms[roomID] = struct{}{}
	for _, evt := range evts {
		pe.unlockedUpdateUser(id.UserID(evt.GetStateKey()), evt.RoomID, evt.Content.AsMember().Membership)
	}
}

func isInRoom(membership event.Membership) bool {
	switch membership {
	case event.MembershipJoin, event.MembershipInvite, event.MembershipKnock:
		return true
	}
	return false
}

func (pe *PolicyEvaluator) updateUser(userID id.UserID, roomID id.RoomID, membership event.Membership) bool {
	pe.usersLock.Lock()
	defer pe.usersLock.Unlock()
	_, isProtected := pe.protectedRooms[roomID]
	if !isProtected {
		return false
	}
	return pe.unlockedUpdateUser(userID, roomID, membership)
}

func (pe *PolicyEvaluator) unlockedUpdateUser(userID id.UserID, roomID id.RoomID, membership event.Membership) bool {
	add := isInRoom(membership)
	if add {
		if !slices.Contains(pe.users[userID], roomID) {
			pe.users[userID] = append(pe.users[userID], roomID)
			return true
		}
	} else if idx := slices.Index(pe.users[userID], roomID); idx >= 0 {
		deleted := slices.Delete(pe.users[userID], idx, idx+1)
		if len(deleted) == 0 {
			delete(pe.users, userID)
		} else {
			pe.users[userID] = deleted
		}
	}
	return false
}
