package policyeval

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exslices"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (pe *PolicyEvaluator) CompileACL() (*event.ServerACLEventContent, time.Duration) {
	start := time.Now()
	rules := pe.Store.ListServerRules(pe.GetWatchedListsForACLs())
	acl := event.ServerACLEventContent{
		Allow: []string{"*"},
		Deny:  make([]string, 0, len(rules)),

		AllowIPLiterals: false,
	}
	for entity, policy := range rules {
		if policy.Pattern.Match(pe.Bot.ServerName) {
			continue
		}
		if policy.Recommendation != event.PolicyRecommendationUnban {
			acl.Deny = append(acl.Deny, entity)
		}
	}
	slices.Sort(acl.Deny)
	return &acl, time.Since(start)
}

func (pe *PolicyEvaluator) DeferredUpdateACL() {
	select {
	case pe.aclDeferChan <- struct{}{}:
	default:
	}
}

const aclDeferTime = 15 * time.Second

func (pe *PolicyEvaluator) aclDeferLoop() {
	ctx := pe.Bot.Log.With().
		Str("action", "deferred acl update").
		Stringer("management_room", pe.ManagementRoom).
		Logger().
		WithContext(context.Background())
	after := time.NewTimer(aclDeferTime)
	after.Stop()
	for {
		select {
		case <-pe.aclDeferChan:
			after.Reset(aclDeferTime)
		case <-after.C:
			pe.UpdateACL(ctx)
		}
	}
}

func (pe *PolicyEvaluator) UpdateACL(ctx context.Context) {
	log := zerolog.Ctx(ctx)
	pe.aclLock.Lock()
	defer pe.aclLock.Unlock()
	newACL, compileDur := pe.CompileACL()
	pe.protectedRoomsLock.RLock()
	changedRooms := make(map[id.RoomID][]string, len(pe.protectedRooms))
	for roomID, meta := range pe.protectedRooms {
		if !meta.ApplyACL {
			continue
		}
		if meta.ACL == nil || !slices.Equal(meta.ACL.Deny, newACL.Deny) {
			changedRooms[roomID] = meta.ACL.Deny
		}
	}
	pe.protectedRoomsLock.RUnlock()
	if len(changedRooms) == 0 {
		log.Info().
			Dur("compile_duration", compileDur).
			Msg("No server ACL changes to send")
		return
	}
	log.Info().
		Int("room_count", len(changedRooms)).
		Any("new_acl", newACL).
		Dur("compile_duration", compileDur).
		Msg("Sending updated server ACL event")
	var wg sync.WaitGroup
	wg.Add(len(changedRooms))
	var successCount atomic.Int32
	for roomID, oldACLDeny := range changedRooms {
		go func(roomID id.RoomID, oldACLDeny []string) {
			defer wg.Done()
			removed, added := exslices.SortedDiff(oldACLDeny, newACL.Deny, strings.Compare)
			if pe.DryRun {
				log.Debug().
					Stringer("room_id", roomID).
					Strs("deny_added", added).
					Strs("deny_removed", removed).
					Msg("Dry run: would send server ACL to room")
				successCount.Add(1)
				return
			}
			resp, err := pe.Bot.SendStateEvent(ctx, roomID, event.StateServerACL, "", newACL)
			if err != nil {
				log.Err(err).
					Strs("deny_added", added).
					Strs("deny_removed", removed).
					Stringer("room_id", roomID).
					Msg("Failed to send server ACL to room")
				pe.sendNotice(ctx, "Failed to send server ACL to room %s: %v", roomID, err)
			} else {
				log.Debug().
					Stringer("room_id", roomID).
					Stringer("event_id", resp.EventID).
					Strs("deny_added", added).
					Strs("deny_removed", removed).
					Msg("Sent new server ACL to room")
				successCount.Add(1)
			}
		}(roomID, oldACLDeny)
	}
	wg.Wait()
	pe.protectedRoomsLock.Lock()
	for roomID := range changedRooms {
		pe.protectedRooms[roomID].ACL = newACL
	}
	pe.protectedRoomsLock.Unlock()
	log.Info().
		Int("room_count", len(changedRooms)).
		Int32("success_count", successCount.Load()).
		Msg("Finished sending server ACL updates")
	pe.sendNotice(ctx, "Successfully sent updated server ACL to %d/%d rooms", successCount.Load(), len(changedRooms))
}
