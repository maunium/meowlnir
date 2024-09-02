package policyeval

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exsync"
	"go.mau.fi/util/ptr"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/config"
	"go.mau.fi/meowlnir/policylist"
)

type PolicyEvaluator struct {
	Client *mautrix.Client
	Store  *policylist.Store

	ManagementRoom    id.RoomID
	Admins            *exsync.Set[id.UserID]
	ProtectedRooms    *exsync.Set[id.RoomID]
	Subscriptions     *exsync.Set[id.RoomID]
	SubscriptionsList atomic.Pointer[[]id.RoomID]

	configLock sync.Mutex

	users     map[id.UserID][]id.RoomID
	usersLock sync.RWMutex
}

func NewPolicyEvaluator(client *mautrix.Client, store *policylist.Store, managementRoom id.RoomID) *PolicyEvaluator {
	pe := &PolicyEvaluator{
		Client:         client,
		Store:          store,
		ManagementRoom: managementRoom,
		Admins:         exsync.NewSet[id.UserID](),
		ProtectedRooms: exsync.NewSet[id.RoomID](),
		Subscriptions:  exsync.NewSet[id.RoomID](),
		users:          make(map[id.UserID][]id.RoomID),
	}
	pe.SubscriptionsList.Store(ptr.Ptr([]id.RoomID{}))
	return pe
}

func (pe *PolicyEvaluator) sendNotice(ctx context.Context, message string, args ...any) {
	if len(args) > 0 {
		message = fmt.Sprintf(message, args...)
	}
	content := format.RenderMarkdown(message, true, false)
	content.MsgType = event.MsgNotice
	_, err := pe.Client.SendMessageEvent(ctx, pe.ManagementRoom, event.EventMessage, &content)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Msg("Failed to send management room message")
	}
}

func (pe *PolicyEvaluator) Load(ctx context.Context) {
	err := pe.tryLoad(ctx)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to load initial state")
		// TODO send notice to room
	} else {
		zerolog.Ctx(ctx).Info().Msg("Loaded initial state")
	}
}

func (pe *PolicyEvaluator) tryLoad(ctx context.Context) error {
	pe.sendNotice(ctx, "Loading initial state...")
	pe.configLock.Lock()
	defer pe.configLock.Unlock()
	state, err := pe.Client.State(ctx, pe.ManagementRoom)
	if err != nil {
		return fmt.Errorf("failed to get management room state: %w", err)
	}
	var errors []string
	if evt, ok := state[event.StatePowerLevels][""]; !ok {
		return fmt.Errorf("no power level event found in management room")
	} else if errMsg := pe.handlePowerLevels(evt); errMsg != "" {
		errors = append(errors, errMsg)
	}
	if evt, ok := state[config.StateWatchedLists][""]; !ok {
		zerolog.Ctx(ctx).Info().Msg("No watched lists event found in management room")
	} else {
		errorMsgs := pe.handleWatchedLists(ctx, evt, true)
		errors = append(errors, errorMsgs...)
	}
	if evt, ok := state[config.StateProtectedRooms][""]; !ok {
		zerolog.Ctx(ctx).Info().Msg("No protected rooms event found in management room")
	} else {
		errorMsgs := pe.handleProtectedRooms(ctx, evt, true)
		errors = append(errors, errorMsgs...)
	}
	pe.usersLock.Lock()
	userCount := len(pe.users)
	pe.usersLock.Unlock()
	if len(errors) > 0 {
		pe.sendNotice(ctx, "Errors occurred during initialization:\n\n%s\n\nProtecting %d rooms with %d users using %d lists.", strings.Join(errors, "\n"), pe.ProtectedRooms.Size(), userCount, pe.Subscriptions.Size())
	} else {
		pe.sendNotice(ctx, "Initialization completed successfully. Protecting %d rooms with %d users using %d lists.", pe.ProtectedRooms.Size(), userCount, pe.Subscriptions.Size())
	}
	return nil
}

func (pe *PolicyEvaluator) IsSubscribed(roomID id.RoomID) bool {
	return pe.Subscriptions.Has(roomID)
}

func (pe *PolicyEvaluator) Subscribe(ctx context.Context, roomID id.RoomID) error {
	if pe.IsSubscribed(roomID) {
		return nil
	}
	if !pe.Store.Contains(roomID) {
		state, err := pe.Client.State(ctx, roomID)
		if err != nil {
			return fmt.Errorf("failed to get room state: %w", err)
		}
		pe.Store.Add(roomID, state)
	}
	pe.Subscriptions.Add(roomID)
	pe.SubscriptionsList.Store(ptr.Ptr(append(*pe.SubscriptionsList.Load(), roomID)))
	return nil
}

func (pe *PolicyEvaluator) Protect(ctx context.Context, roomID id.RoomID) error {
	members, err := pe.Client.Members(ctx, roomID)
	if err != nil {
		return fmt.Errorf("failed to get room members: %w", err)
	}
	pe.updateManyUsers(members.Chunk)
	pe.ProtectedRooms.Add(roomID)
	return nil
}

func (pe *PolicyEvaluator) HandleConfigChange(ctx context.Context, evt *event.Event) {
	pe.configLock.Lock()
	defer pe.configLock.Unlock()
	var errorMsg string
	switch evt.Type {
	case event.StatePowerLevels:
		errorMsg = pe.handlePowerLevels(evt)
	case config.StateWatchedLists:
		errorMsgs := pe.handleWatchedLists(ctx, evt, false)
		errorMsg = strings.Join(errorMsgs, "\n")
	case config.StateProtectedRooms:
		errorMsgs := pe.handleProtectedRooms(ctx, evt, false)
		errorMsg = strings.Join(errorMsgs, "\n")
	}
	if errorMsg != "" {
		pe.sendNotice(ctx, "Errors occurred while handling config change:\n\n%s", errorMsg)
	}
}

func (pe *PolicyEvaluator) handlePowerLevels(evt *event.Event) string {
	content, ok := evt.Content.Parsed.(*event.PowerLevelsEventContent)
	if !ok {
		return "* Failed to parse power level event"
	}
	adminLevel := content.GetEventLevel(config.StateWatchedLists)
	admins := exsync.NewSet[id.UserID]()
	for user, level := range content.Users {
		if level > adminLevel {
			admins.Add(user)
		}
	}
	pe.Admins.ReplaceAll(admins)
	return ""
}

func (pe *PolicyEvaluator) handleWatchedLists(ctx context.Context, evt *event.Event, isInitial bool) (out []string) {
	content, ok := evt.Content.Parsed.(*config.WatchedListsEventContent)
	if !ok {
		return []string{"* Failed to parse watched lists event"}
	}
	for roomID, listInfo := range content.Lists {
		err := pe.Subscribe(ctx, roomID)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Stringer("list_id", roomID).Msg("Failed to subscribe to watched list")
			out = append(out, fmt.Sprintf("* Failed to watch list [%s](%s): %v", listInfo.Name, roomID.URI().MatrixToURL(), err))
		}
	}
	return
}

func (pe *PolicyEvaluator) handleProtectedRooms(ctx context.Context, evt *event.Event, isInitial bool) (out []string) {
	content, ok := evt.Content.Parsed.(*config.ProtectedRoomsEventContent)
	if !ok {
		return []string{"* Failed to parse protected rooms event"}
	}
	for _, roomID := range content.Rooms {
		err := pe.Protect(ctx, roomID)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Stringer("protected_room", roomID).Msg("Failed to protect room")
			out = append(out, fmt.Sprintf("* Failed to protect room [%s](%s): %v", roomID, roomID.URI().MatrixToURL(), err))
		}
	}
	return
}

func (pe *PolicyEvaluator) HandlePolicyListChange(ctx context.Context, policyRoom id.RoomID, added, removed *policylist.Policy) {
	if pe.IsSubscribed(policyRoom) {
		return
	}
	zerolog.Ctx(ctx).Info().
		Any("added", added).
		Any("removed", removed).
		Msg("Policy list change")
}

func isInRoom(membership event.Membership) bool {
	switch membership {
	case event.MembershipJoin, event.MembershipInvite, event.MembershipKnock:
		return true
	}
	return false
}

func (pe *PolicyEvaluator) HandleMember(ctx context.Context, evt *event.Event) {
	if pe.ProtectedRooms.Has(evt.RoomID) {
		return
	}
	checkRules := pe.updateUser(id.UserID(evt.GetStateKey()), evt.RoomID, evt.Content.AsMember().Membership)
	if checkRules {
		match := pe.Store.MatchUser(*pe.SubscriptionsList.Load(), id.UserID(evt.GetStateKey()))
		if match != nil {
			zerolog.Ctx(ctx).Info().
				Str("user_id", evt.GetStateKey()).
				Any("recommendation", match.Recommendations()).
				Any("matches", match).
				Msg("Matched user in membership event")
		}
	}
}

func (pe *PolicyEvaluator) updateUser(userID id.UserID, roomID id.RoomID, membership event.Membership) bool {
	pe.usersLock.Lock()
	defer pe.usersLock.Unlock()
	return pe.unlockedUpdateUser(userID, roomID, membership)
}

func (pe *PolicyEvaluator) updateManyUsers(evts []*event.Event) {
	pe.usersLock.Lock()
	defer pe.usersLock.Unlock()
	for _, evt := range evts {
		pe.unlockedUpdateUser(id.UserID(evt.GetStateKey()), evt.RoomID, evt.Content.AsMember().Membership)
	}
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
