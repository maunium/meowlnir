package policyeval

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exslices"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/config"
)

func (pe *PolicyEvaluator) IsWatchingList(roomID id.RoomID) bool {
	pe.watchedListsLock.RLock()
	meta, watched := pe.watchedListsMap[roomID]
	pe.watchedListsLock.RUnlock()
	return watched && (meta.InRoom || !pe.Untrusted)
}

func (pe *PolicyEvaluator) GetWatchedListMetaEvenIfNotInRoom(roomID id.RoomID) *config.WatchedPolicyList {
	pe.watchedListsLock.RLock()
	meta := pe.watchedListsMap[roomID]
	pe.watchedListsLock.RUnlock()
	return meta
}

func (pe *PolicyEvaluator) GetWatchedListMeta(roomID id.RoomID) *config.WatchedPolicyList {
	meta := pe.GetWatchedListMetaEvenIfNotInRoom(roomID)
	if meta != nil && !meta.InRoom && pe.Untrusted {
		return nil
	}
	return meta
}

func (pe *PolicyEvaluator) FindListByShortcode(shortcode string) *config.WatchedPolicyList {
	shortcode = strings.ToLower(shortcode)
	pe.watchedListsLock.RLock()
	defer pe.watchedListsLock.RUnlock()
	for _, meta := range pe.watchedListsMap {
		if strings.ToLower(meta.Shortcode) == shortcode {
			if !meta.InRoom && pe.Untrusted {
				return nil
			}
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

func (pe *PolicyEvaluator) GetWatchedListsForMatch() []id.RoomID {
	if pe.Untrusted {
		return pe.GetWatchedLists()
	}
	return nil
}

func (pe *PolicyEvaluator) handleWatchedLists(ctx context.Context, evt *event.Event, isInitial bool) (output, errors []string) {
	content, ok := evt.Content.Parsed.(*config.WatchedListsEventContent)
	if !ok {
		return nil, []string{"* Failed to parse watched lists event"}
	}
	var wg sync.WaitGroup
	var outLock sync.Mutex
	wg.Add(len(content.Lists))
	failed := make(map[id.RoomID]struct{})
	for _, listInfo := range content.Lists {
		doLoad := func() {
			defer wg.Done()
			var errMsg string
			if pe.Untrusted {
				state, err := pe.Bot.FullStateEvent(ctx, listInfo.RoomID, event.StateMember, pe.Bot.UserID.String())
				if err != nil {
					zerolog.Ctx(ctx).Err(err).Stringer("room_id", listInfo.RoomID).Msg("Failed to load bot member event in watched list")
					errMsg = fmt.Sprintf("* Failed to check membership in %s: %v", format.MarkdownMentionRoomID(listInfo.Name, listInfo.RoomID), err)
				} else if state == nil || state.Content.AsMember().Membership != event.MembershipJoin {
					errMsg = fmt.Sprintf("* Not a member of %s", format.MarkdownMentionRoomID(listInfo.Name, listInfo.RoomID))
				}
			}
			if errMsg == "" && !pe.Store.Contains(listInfo.RoomID) {
				state, err := pe.Bot.State(ctx, listInfo.RoomID)
				if err != nil {
					zerolog.Ctx(ctx).Err(err).Stringer("room_id", listInfo.RoomID).Msg("Failed to load state of watched list")
				} else {
					pe.Store.Add(listInfo.RoomID, state)
				}
			}
			if errMsg != "" {
				outLock.Lock()
				if pe.Untrusted {
					failed[listInfo.RoomID] = struct{}{}
				}
				errors = append(errors, errMsg)
				outLock.Unlock()
			}
		}
		if pe.DB.Dialect == dbutil.SQLite {
			// Load rooms synchronously on SQLite to avoid lots of things trying to write at once
			pe.Store.WithLoadLock(listInfo.RoomID, doLoad)
		} else {
			go pe.Store.WithLoadLock(listInfo.RoomID, doLoad)
		}
	}
	wg.Wait()
	watchedList := make([]id.RoomID, 0, len(content.Lists))
	aclWatchedList := make([]id.RoomID, 0, len(content.Lists))
	watchedMap := make(map[id.RoomID]*config.WatchedPolicyList, len(content.Lists))
	for _, listInfo := range content.Lists {
		if _, alreadyWatched := watchedMap[listInfo.RoomID]; alreadyWatched {
			errors = append(errors, fmt.Sprintf("* Duplicate watched list %s", format.MarkdownMentionRoomID(listInfo.Name, listInfo.RoomID)))
		} else {
			_, listFailed := failed[listInfo.RoomID]
			listInfo.InRoom = !listFailed
			watchedMap[listInfo.RoomID] = &listInfo
			if !listInfo.DontApply && !listFailed {
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
			output = append(output, fmt.Sprintf("* Subscribed to %s", format.MarkdownMentionRoomID(pe.GetWatchedListMetaEvenIfNotInRoom(roomID).Name, roomID)))
		}
		for _, roomID := range noApplySubscribed {
			if !slices.Contains(subscribed, roomID) {
				output = append(output, fmt.Sprintf("* Subscribed to %s without applying policies", format.MarkdownMentionRoomID(pe.GetWatchedListMetaEvenIfNotInRoom(roomID).Name, roomID)))
			}
		}
		for _, roomID := range unsubscribed {
			output = append(output, fmt.Sprintf("* Unsubscribed from %s", format.MarkdownMentionRoomID("", roomID)))
		}
		for _, roomID := range noApplyUnsubscribed {
			if !slices.Contains(unsubscribed, roomID) {
				output = append(output, fmt.Sprintf("* Unsubscribed from %s (policies weren't being applied)", format.MarkdownMentionRoomID("", roomID)))
			}
		}
		aclUnsubscribed, aclSubscribed := exslices.Diff(oldACLWatchedList, aclWatchedList)
		for _, roomID := range aclSubscribed {
			if !slices.Contains(subscribed, roomID) {
				output = append(output, fmt.Sprintf("* Subscribed to server ACLs in %s", format.MarkdownMentionRoomID(pe.GetWatchedListMetaEvenIfNotInRoom(roomID).Name, roomID)))
			}
		}
		for _, roomID := range aclUnsubscribed {
			if !slices.Contains(unsubscribed, roomID) {
				output = append(output, fmt.Sprintf("* Unsubscribed from server ACLs in %s", format.MarkdownMentionRoomID(pe.GetWatchedListMetaEvenIfNotInRoom(roomID).Name, roomID)))
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
