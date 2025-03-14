package policyeval

import (
	"context"
	"slices"
	"sync"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (pe *PolicyEvaluator) CompileACL() *event.ServerACLEventContent {
	rules := pe.Store.ListServerRules(pe.GetWatchedLists())
	acl := event.ServerACLEventContent{
		Allow: []string{"*"},
		Deny:  make([]string, 0, len(rules)),

		AllowIPLiterals: false,
	}
	botServer := pe.Bot.UserID.Homeserver()
	for entity, policy := range rules {
		if policy.Pattern.Match(botServer) {
			continue
		}
		if policy.Recommendation != event.PolicyRecommendationUnban {
			acl.Deny = append(acl.Deny, entity)
		}
	}
	slices.Sort(acl.Deny)
	return &acl
}

func (pe *PolicyEvaluator) UpdateACL(ctx context.Context) {
	log := zerolog.Ctx(ctx)
	pe.aclLock.Lock()
	defer pe.aclLock.Unlock()
	newACL := pe.CompileACL()
	pe.protectedRoomsLock.RLock()
	changedRooms := make([]id.RoomID, 0, len(pe.protectedRooms))
	for roomID, meta := range pe.protectedRooms {
		if meta.ACL == nil || !slices.Equal(meta.ACL.Deny, newACL.Deny) {
			changedRooms = append(changedRooms, roomID)
		}
	}
	pe.protectedRoomsLock.RUnlock()
	if len(changedRooms) == 0 {
		log.Info().Msg("No server ACL changes to send")
		return
	}
	log.Info().
		Int("room_count", len(changedRooms)).
		Any("new_acl", newACL).
		Msg("Sending updated server ACL event")
	var wg sync.WaitGroup
	wg.Add(len(changedRooms))
	for _, roomID := range changedRooms {
		go func(roomID id.RoomID) {
			defer wg.Done()
			if pe.DryRun {
				log.Debug().
					Stringer("room_id", roomID).
					Msg("Dry run: would send server ACL to room")
				return
			}
			resp, err := pe.Bot.SendStateEvent(ctx, roomID, event.StateServerACL, "", newACL)
			if err != nil {
				log.Err(err).Stringer("room_id", roomID).Msg("Failed to send server ACL to room")
			} else {
				log.Debug().
					Stringer("room_id", roomID).
					Stringer("event_id", resp.EventID).
					Msg("Sent new server ACL to room")
			}
		}(roomID)
	}
	wg.Wait()
	pe.protectedRoomsLock.Lock()
	for _, roomID := range changedRooms {
		pe.protectedRooms[roomID].ACL = newACL
	}
	pe.protectedRoomsLock.Unlock()
	log.Info().Int("room_count", len(changedRooms)).Msg("Finished sending server ACL updates")
}
