package policyeval

import (
	"context"
	"fmt"
	"sync"

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

func (pe *PolicyEvaluator) GetWatchedLists() []id.RoomID {
	pe.watchedListsLock.RLock()
	defer pe.watchedListsLock.RUnlock()
	return pe.watchedListsList
}

func (pe *PolicyEvaluator) handleWatchedLists(ctx context.Context, evt *event.Event, isInitial bool) (out []string) {
	content, ok := evt.Content.Parsed.(*config.WatchedListsEventContent)
	if !ok {
		return []string{"* Failed to parse watched lists event"}
	}
	watchedList := make([]id.RoomID, 0, len(content.Lists))
	watchedMap := make(map[id.RoomID]*config.WatchedPolicyList, len(content.Lists))
	var outLock sync.Mutex
	var wg sync.WaitGroup
	for _, listInfo := range content.Lists {
		if _, alreadyWatched := watchedMap[listInfo.RoomID]; alreadyWatched {
			outLock.Lock()
			out = append(out, fmt.Sprintf("* Duplicate watched list [%s](%s)", listInfo.Name, listInfo.RoomID.URI().MatrixToURL()))
			outLock.Unlock()
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !pe.Store.Contains(listInfo.RoomID) {
				state, err := pe.Client.State(ctx, listInfo.RoomID)
				if err != nil {
					outLock.Lock()
					out = append(out, fmt.Sprintf("* Failed to get room state for [%s](%s): %v", listInfo.Name, listInfo.RoomID.URI().MatrixToURL(), err))
					outLock.Unlock()
					return
				}
				pe.Store.Add(listInfo.RoomID, state)
			}
			outLock.Lock()
			watchedMap[listInfo.RoomID] = &listInfo
			watchedList = append(watchedList, listInfo.RoomID)
			outLock.Unlock()
		}()
	}
	wg.Wait()
	pe.watchedListsLock.Lock()
	oldWatchedList := pe.watchedListsList
	pe.watchedListsMap = watchedMap
	pe.watchedListsList = watchedList
	pe.watchedListsLock.Unlock()
	if !isInitial {
		unsubscribed, subscribed := exslices.Diff(oldWatchedList, watchedList)
		go func(ctx context.Context) {
			if len(unsubscribed) > 0 {
				pe.ReevaluateAffectedByLists(ctx, unsubscribed)
			}
			if len(subscribed) > 0 || len(unsubscribed) > 0 {
				pe.EvaluateAll(ctx)
			}
		}(context.WithoutCancel(ctx))
	}
	return
}