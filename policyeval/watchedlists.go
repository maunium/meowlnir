package policyeval

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exslices"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/config"
)

func (pe *PolicyEvaluator) IsWatchingList(roomID id.RoomID) bool {
	pe.watchedListsLock.RLock()
	_, watched := pe.watchedListsMap[roomID]
	pe.watchedListsLock.RUnlock()
	return watched
}

func (pe *PolicyEvaluator) GetWatchedListMeta(roomID id.RoomID) *config.WatchedPolicyList {
	pe.watchedListsLock.RLock()
	meta := pe.watchedListsMap[roomID]
	pe.watchedListsLock.RUnlock()
	return meta
}

func (pe *PolicyEvaluator) FindListByShortcode(shortcode string) *config.WatchedPolicyList {
	shortcode = strings.ToLower(shortcode)
	pe.watchedListsLock.RLock()
	defer pe.watchedListsLock.RUnlock()
	for _, meta := range pe.watchedListsMap {
		if strings.ToLower(meta.Shortcode) == shortcode {
			return meta
		}
	}
	return nil
}

func (pe *PolicyEvaluator) GetWatchedLists() []id.RoomID {
	pe.watchedListsLock.RLock()
	defer pe.watchedListsLock.RUnlock()
	return pe.watchedListsList
}

func (pe *PolicyEvaluator) GetWatchedListsForACLs() []id.RoomID {
	pe.watchedListsLock.RLock()
	defer pe.watchedListsLock.RUnlock()
	return pe.watchedListsForACLs
}

func (pe *PolicyEvaluator) handleWatchedLists(ctx context.Context, evt *event.Event, isInitial bool) (output, errors []string) {
	content, ok := evt.Content.Parsed.(*config.WatchedListsEventContent)
	if !ok {
		return nil, []string{"* Failed to parse watched lists event"}
	}
	var wg sync.WaitGroup
	var outLock sync.Mutex
	wg.Add(len(content.Lists))
	for _, listInfo := range content.Lists {
		go func() {
			defer wg.Done()
			if !pe.Store.Contains(listInfo.RoomID) {
				state, err := pe.Bot.State(ctx, listInfo.RoomID)
				if err != nil {
					zerolog.Ctx(ctx).Err(err).Stringer("room_id", listInfo.RoomID).Msg("Failed to load state of watched list")
					outLock.Lock()
					errors = append(errors, fmt.Sprintf("* Failed to get room state for [%s](%s): %v", listInfo.Name, listInfo.RoomID.URI().MatrixToURL(), err))
					outLock.Unlock()
					return
				}
				pe.Store.Add(listInfo.RoomID, state)
			}
		}()
	}
	wg.Wait()
	watchedList := make([]id.RoomID, 0, len(content.Lists))
	aclWatchedList := make([]id.RoomID, 0, len(content.Lists))
	watchedMap := make(map[id.RoomID]*config.WatchedPolicyList, len(content.Lists))
	for _, listInfo := range content.Lists {
		if _, alreadyWatched := watchedMap[listInfo.RoomID]; alreadyWatched {
			errors = append(errors, fmt.Sprintf("* Duplicate watched list [%s](%s)", listInfo.Name, listInfo.RoomID.URI().MatrixToURL()))
		} else {
			watchedMap[listInfo.RoomID] = &listInfo
			if !listInfo.DontApply {
				watchedList = append(watchedList, listInfo.RoomID)
				if !listInfo.DontApplyACL {
					aclWatchedList = append(aclWatchedList, listInfo.RoomID)
				}
			}
		}
	}
	pe.watchedListsLock.Lock()
	oldWatchedList := pe.watchedListsList
	oldACLWatchedList := pe.watchedListsForACLs
	oldFullWatchedList := slices.Collect(maps.Keys(pe.watchedListsMap))
	pe.watchedListsMap = watchedMap
	pe.watchedListsList = watchedList
	pe.watchedListsForACLs = aclWatchedList
	pe.watchedListsEvent = content
	pe.watchedListsLock.Unlock()
	if !isInitial {
		unsubscribed, subscribed := exslices.Diff(oldWatchedList, watchedList)
		noApplyUnsubscribed, noApplySubscribed := exslices.Diff(oldFullWatchedList, slices.Collect(maps.Keys(pe.watchedListsMap)))
		for _, roomID := range subscribed {
			output = append(output, fmt.Sprintf("* Subscribed to %s [%s](%s)", pe.GetWatchedListMeta(roomID).Name, roomID, roomID.URI().MatrixToURL()))
		}
		for _, roomID := range noApplySubscribed {
			if !slices.Contains(subscribed, roomID) {
				output = append(output, fmt.Sprintf("* Subscribed to %s [%s](%s) without applying policies", pe.GetWatchedListMeta(roomID).Name, roomID, roomID.URI().MatrixToURL()))
			}
		}
		for _, roomID := range unsubscribed {
			output = append(output, fmt.Sprintf("* Unsubscribed from [%s](%s)", roomID, roomID.URI().MatrixToURL()))
		}
		for _, roomID := range noApplyUnsubscribed {
			if !slices.Contains(unsubscribed, roomID) {
				output = append(output, fmt.Sprintf("* Unsubscribed from [%s](%s) (policies weren't being applied)", roomID, roomID.URI().MatrixToURL()))
			}
		}
		aclUnsubscribed, aclSubscribed := exslices.Diff(oldACLWatchedList, aclWatchedList)
		for _, roomID := range aclSubscribed {
			if !slices.Contains(subscribed, roomID) {
				output = append(output, fmt.Sprintf("* Subscribed to server ACLs in %s [%s](%s)", pe.GetWatchedListMeta(roomID).Name, roomID, roomID.URI().MatrixToURL()))
			}
		}
		for _, roomID := range aclUnsubscribed {
			if !slices.Contains(unsubscribed, roomID) {
				output = append(output, fmt.Sprintf("* Unsubscribed from server ACLs in %s [%s](%s)", pe.GetWatchedListMeta(roomID).Name, roomID, roomID.URI().MatrixToURL()))
			}
		}
		go func(ctx context.Context) {
			if len(unsubscribed) > 0 {
				pe.ReevaluateAffectedByLists(ctx, unsubscribed)
			}
			if len(subscribed) > 0 || len(unsubscribed) > 0 {
				pe.EvaluateAll(ctx)
			}
			if len(aclSubscribed) > 0 || len(aclUnsubscribed) > 0 {
				pe.UpdateACL(ctx)
			}
		}(context.WithoutCancel(ctx))
	}
	return
}
