package policyeval

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/config"
	"go.mau.fi/meowlnir/util"
)

func (pe *PolicyEvaluator) GetProtectedRooms() []id.RoomID {
	pe.protectedRoomsLock.RLock()
	rooms := slices.Collect(maps.Keys(pe.protectedRooms))
	pe.protectedRoomsLock.RUnlock()
	return rooms
}

func (pe *PolicyEvaluator) IsProtectedRoom(roomID id.RoomID) bool {
	pe.protectedRoomsLock.RLock()
	_, protected := pe.protectedRooms[roomID]
	pe.protectedRoomsLock.RUnlock()
	return protected
}

func (pe *PolicyEvaluator) HandleProtectedRoomMeta(ctx context.Context, evt *event.Event) {
	switch evt.Type {
	case event.StatePowerLevels:
		pe.handleProtectedRoomPowerLevels(ctx, evt)
	case event.StateRoomName:
		pe.protectedRoomsLock.Lock()
		meta, ok := pe.protectedRooms[evt.RoomID]
		if ok {
			meta.Name = evt.Content.AsRoomName().Name
		}
		pe.protectedRoomsLock.Unlock()
	case event.StateServerACL:
		pe.protectedRoomsLock.Lock()
		meta, ok := pe.protectedRooms[evt.RoomID]
		if ok {
			meta.ACL, ok = evt.Content.Parsed.(*event.ServerACLEventContent)
			if !ok {
				zerolog.Ctx(ctx).Warn().
					Stringer("room_id", evt.RoomID).
					Msg("Failed to parse new server ACL in room")
			} else {
				slices.Sort(meta.ACL.Deny)
			}
			// TODO notify management room about change?
		}
		pe.protectedRoomsLock.Unlock()
	}
}

func (pe *PolicyEvaluator) handleProtectedRoomPowerLevels(ctx context.Context, evt *event.Event) {
	powerLevels := evt.Content.AsPowerLevels()
	ownLevel := powerLevels.GetUserLevel(pe.Bot.UserID)
	minLevel := max(powerLevels.Ban(), powerLevels.Redact())
	pe.protectedRoomsLock.RLock()
	meta, isProtecting := pe.protectedRooms[evt.RoomID]
	_, wantToProtect := pe.wantToProtect[evt.RoomID]
	pe.protectedRoomsLock.RUnlock()
	if meta != nil && meta.ApplyACL {
		minLevel = max(minLevel, powerLevels.GetEventLevel(event.StateServerACL))
	}
	if isProtecting && ownLevel < minLevel {
		pe.sendNotice(ctx, "⚠️ Bot no longer has sufficient power level in [%s](%s) (have %d, minimum %d)", evt.RoomID, evt.RoomID.URI().MatrixToURL(), ownLevel, minLevel)
	} else if wantToProtect && ownLevel >= minLevel {
		_, errMsg := pe.tryProtectingRoom(ctx, nil, evt.RoomID, true)
		if errMsg != "" {
			pe.sendNotice(ctx, "Retried protecting room after power level change, but failed: %s", strings.TrimPrefix(errMsg, "* "))
		} else {
			pe.sendNotice(ctx, "Power levels corrected, now protecting [%s](%s)", evt.RoomID, evt.RoomID.URI().MatrixToURL())
		}
	}
}

func (pe *PolicyEvaluator) lockJoin(roomID id.RoomID) func() {
	pe.protectedRoomsLock.Lock()
	_, isJoining := pe.isJoining[roomID]
	pe.isJoining[roomID] = struct{}{}
	pe.protectedRoomsLock.Unlock()
	if isJoining {
		return nil
	}
	return func() {
		pe.protectedRoomsLock.Lock()
		delete(pe.isJoining, roomID)
		pe.protectedRoomsLock.Unlock()
	}
}

func (pe *PolicyEvaluator) tryProtectingRoom(ctx context.Context, joinedRooms *mautrix.RespJoinedRooms, roomID id.RoomID, doReeval bool) (*mautrix.RespMembers, string) {
	if roomID == pe.ManagementRoom {
		return nil, "* The management room can't be a protected room"
	} else if claimer := pe.claimProtected(roomID, pe, true); claimer != pe {
		if claimer != nil && claimer.Bot.UserID == pe.Bot.UserID {
			return nil, fmt.Sprintf("* Room [%s](%s) is already protected by [%s](%s)", roomID, roomID.URI().MatrixToURL(), claimer.ManagementRoom, claimer.ManagementRoom.URI().MatrixToURL())
		} else {
			if claimer != nil {
				zerolog.Ctx(ctx).Debug().
					Stringer("claimer_user_id", claimer.Bot.UserID).
					Stringer("claimer_room_id", claimer.ManagementRoom).
					Msg("Failed to protect room that's already claimed by another bot")
			} else {
				zerolog.Ctx(ctx).Warn().Msg("Failed to protect room, but no existing claimer found, likely a management room")
			}
			return nil, fmt.Sprintf("* Room [%s](%s) is already protected by another bot", roomID, roomID.URI().MatrixToURL())
		}
	}
	var err error
	if joinedRooms == nil {
		joinedRooms, err = pe.Bot.JoinedRooms(ctx)
		if err != nil {
			return nil, fmt.Sprintf("* Failed to get joined rooms: %v", err)
		}
	}
	pe.markAsWantToProtect(roomID)
	if !slices.Contains(joinedRooms.JoinedRooms, roomID) {
		unlock := pe.lockJoin(roomID)
		if unlock == nil {
			return nil, ""
		}
		defer unlock()
		_, err = pe.Bot.JoinRoom(ctx, roomID.String(), nil)
		if err != nil {
			return nil, fmt.Sprintf("* Bot is not in protected room [%s](%s) and joining failed: %v", roomID, roomID.URI().MatrixToURL(), err)
		}
	}
	var powerLevels event.PowerLevelsEventContent
	err = pe.Bot.StateEvent(ctx, roomID, event.StatePowerLevels, "", &powerLevels)
	if err != nil {
		return nil, fmt.Sprintf("* Failed to get power levels for [%s](%s): %v", roomID, roomID.URI().MatrixToURL(), err)
	}
	ownLevel := powerLevels.GetUserLevel(pe.Bot.UserID)
	minLevel := max(powerLevels.Ban(), powerLevels.Redact())
	if ownLevel < minLevel && !pe.DryRun {
		return nil, fmt.Sprintf("* Bot does not have sufficient power level in [%s](%s) (have %d, minimum %d)", roomID, roomID.URI().MatrixToURL(), ownLevel, minLevel)
	}
	members, err := pe.Bot.Members(ctx, roomID)
	if err != nil {
		return nil, fmt.Sprintf("* Failed to get room members for [%s](%s): %v", roomID, roomID.URI().MatrixToURL(), err)
	}
	var name event.RoomNameEventContent
	err = pe.Bot.StateEvent(ctx, roomID, event.StateRoomName, "", &name)
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Stringer("room_id", roomID).Msg("Failed to get room name")
	}
	var acl event.ServerACLEventContent
	err = pe.Bot.StateEvent(ctx, roomID, event.StateServerACL, "", &acl)
	if err != nil {
		zerolog.Ctx(ctx).Warn().Err(err).Stringer("room_id", roomID).Msg("Failed to get server ACL")
	}
	slices.Sort(acl.Deny)
	pe.markAsProtectedRoom(roomID, name.Name, &acl, members.Chunk)
	if doReeval {
		memberIDs := make([]id.UserID, len(members.Chunk))
		for i, member := range members.Chunk {
			memberIDs[i] = id.UserID(member.GetStateKey())
		}
		pe.EvaluateAllMembers(ctx, memberIDs)
		pe.UpdateACL(ctx)
	}
	return members, ""
}

func (pe *PolicyEvaluator) handleProtectedRooms(ctx context.Context, evt *event.Event, isInitial bool) (output, errors []string) {
	content, ok := evt.Content.Parsed.(*config.ProtectedRoomsEventContent)
	if !ok {
		return nil, []string{"* Failed to parse protected rooms event"}
	}
	pe.protectedRoomsLock.Lock()
	pe.protectedRoomsEvent = content
	pe.skipACLForRooms = content.SkipACL
	for roomID := range pe.protectedRooms {
		if !slices.Contains(content.Rooms, roomID) {
			delete(pe.protectedRooms, roomID)
			pe.claimProtected(roomID, pe, false)
			output = append(output, fmt.Sprintf("* Stopped protecting room [%s](%s)", roomID, roomID.URI().MatrixToURL()))
		}
	}
	pe.protectedRoomsLock.Unlock()
	joinedRooms, err := pe.Bot.JoinedRooms(ctx)
	if err != nil {
		return output, []string{"* Failed to get joined rooms: ", err.Error()}
	}
	var outLock sync.Mutex
	reevalMembers := make(map[id.UserID]struct{})
	var wg sync.WaitGroup
	for _, roomID := range content.Rooms {
		if pe.IsProtectedRoom(roomID) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			members, errMsg := pe.tryProtectingRoom(ctx, joinedRooms, roomID, false)
			outLock.Lock()
			defer outLock.Unlock()
			if errMsg != "" {
				errors = append(errors, errMsg)
			}
			if !isInitial && members != nil {
				for _, member := range members.Chunk {
					reevalMembers[id.UserID(member.GetStateKey())] = struct{}{}
				}
				output = append(output, fmt.Sprintf("* Started protecting room [%s](%s)", roomID, roomID.URI().MatrixToURL()))
			}
		}()
	}
	wg.Wait()
	if len(reevalMembers) > 0 {
		pe.EvaluateAllMembers(ctx, slices.Collect(maps.Keys(reevalMembers)))
		pe.UpdateACL(ctx)
	}
	return
}

func (pe *PolicyEvaluator) markAsWantToProtect(roomID id.RoomID) {
	pe.protectedRoomsLock.Lock()
	defer pe.protectedRoomsLock.Unlock()
	pe.wantToProtect[roomID] = struct{}{}
}

func (pe *PolicyEvaluator) markAsProtectedRoom(roomID id.RoomID, name string, acl *event.ServerACLEventContent, evts []*event.Event) {
	pe.protectedRoomsLock.Lock()
	defer pe.protectedRoomsLock.Unlock()
	pe.protectedRooms[roomID] = &protectedRoomMeta{Name: name, ACL: acl, ApplyACL: !slices.Contains(pe.skipACLForRooms, roomID)}
	delete(pe.wantToProtect, roomID)
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
	pe.protectedRoomsLock.Lock()
	defer pe.protectedRoomsLock.Unlock()
	_, isProtected := pe.protectedRooms[roomID]
	if !isProtected {
		return false
	}
	return pe.unlockedUpdateUser(userID, roomID, membership)
}

func (pe *PolicyEvaluator) unlockedUpdateUser(userID id.UserID, roomID id.RoomID, membership event.Membership) bool {
	add := isInRoom(membership)
	existingList, ok := pe.protectedRoomMembers[userID]
	if !ok {
		pe.memberHashes[util.SHA256String(string(userID))] = userID
	}
	if add {
		if !slices.Contains(existingList, roomID) {
			pe.protectedRoomMembers[userID] = append(existingList, roomID)
			return true
		}
	} else if idx := slices.Index(existingList, roomID); idx >= 0 {
		pe.protectedRoomMembers[userID] = slices.Delete(existingList, idx, idx+1)
	} else if !ok && membership != event.MembershipBan {
		// Even left users are added to the map to ensure events are redacted if they leave before being banned
		pe.protectedRoomMembers[userID] = []id.RoomID{}
	}
	return false
}
