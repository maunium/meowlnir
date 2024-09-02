package policyeval

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exsync"
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

	ManagementRoom id.RoomID
	Admins         *exsync.Set[id.UserID]

	watchedListsMap  map[id.RoomID]*config.WatchedPolicyList
	watchedListsList []id.RoomID
	watchedListsLock sync.RWMutex

	configLock sync.Mutex

	protectedRooms map[id.RoomID]struct{}
	users          map[id.UserID][]id.RoomID
	usersLock      sync.RWMutex
}

func NewPolicyEvaluator(client *mautrix.Client, store *policylist.Store, managementRoom id.RoomID) *PolicyEvaluator {
	pe := &PolicyEvaluator{
		Client:          client,
		Store:           store,
		ManagementRoom:  managementRoom,
		Admins:          exsync.NewSet[id.UserID](),
		users:           make(map[id.UserID][]id.RoomID),
		watchedListsMap: make(map[id.RoomID]*config.WatchedPolicyList),
		protectedRooms:  make(map[id.RoomID]struct{}),
	}
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
	start := time.Now()
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
	initDuration := time.Since(start)
	start = time.Now()
	pe.EvaluateAll(ctx)
	evalDuration := time.Since(start)
	pe.usersLock.Lock()
	userCount := len(pe.users)
	protectedRoomsCount := len(pe.protectedRooms)
	pe.usersLock.Unlock()
	if len(errors) > 0 {
		pe.sendNotice(ctx,
			"Errors occurred during initialization:\n\n%s\n\nProtecting %d rooms with %d users using %d lists.",
			strings.Join(errors, "\n"), protectedRoomsCount, userCount, len(pe.GetWatchedLists()))
	} else {
		pe.sendNotice(ctx,
			"Initialization completed successfully (took %s to load data and %s to evaluate rules). "+
				"Protecting %d rooms with %d users using %d lists.",
			initDuration, evalDuration, protectedRoomsCount, userCount, len(pe.GetWatchedLists()))
	}
	return nil
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
