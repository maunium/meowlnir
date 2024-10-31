package policyeval

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exsync"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/bot"
	"go.mau.fi/meowlnir/config"
	"go.mau.fi/meowlnir/database"
	"go.mau.fi/meowlnir/policylist"
	"go.mau.fi/meowlnir/synapsedb"
)

type PolicyEvaluator struct {
	Bot       *bot.Bot
	Store     *policylist.Store
	SynapseDB *synapsedb.SynapseDB
	DB        *database.Database
	DryRun    bool

	ManagementRoom id.RoomID
	Admins         *exsync.Set[id.UserID]

	watchedListsMap  map[id.RoomID]*config.WatchedPolicyList
	watchedListsList []id.RoomID
	watchedListsLock sync.RWMutex

	configLock sync.Mutex

	claimProtected       func(roomID id.RoomID, eval *PolicyEvaluator, claim bool) *PolicyEvaluator
	protectedRooms       map[id.RoomID]struct{}
	wantToProtect        map[id.RoomID]struct{}
	protectedRoomMembers map[id.UserID][]id.RoomID
	protectedRoomsLock   sync.RWMutex
}

func NewPolicyEvaluator(
	bot *bot.Bot,
	store *policylist.Store,
	managementRoom id.RoomID,
	db *database.Database,
	synapseDB *synapsedb.SynapseDB,
	claimProtected func(roomID id.RoomID, eval *PolicyEvaluator, claim bool) *PolicyEvaluator,
	dryRun bool,
) *PolicyEvaluator {
	pe := &PolicyEvaluator{
		Bot:                  bot,
		DB:                   db,
		SynapseDB:            synapseDB,
		Store:                store,
		ManagementRoom:       managementRoom,
		Admins:               exsync.NewSet[id.UserID](),
		protectedRoomMembers: make(map[id.UserID][]id.RoomID),
		watchedListsMap:      make(map[id.RoomID]*config.WatchedPolicyList),
		protectedRooms:       make(map[id.RoomID]struct{}),
		wantToProtect:        make(map[id.RoomID]struct{}),
		claimProtected:       claimProtected,

		DryRun: dryRun,
	}
	return pe
}

func (pe *PolicyEvaluator) sendNotice(ctx context.Context, message string, args ...any) {
	pe.Bot.SendNotice(ctx, pe.ManagementRoom, message, args...)
}

func (pe *PolicyEvaluator) sendSuccessReaction(ctx context.Context, eventID id.EventID) {
	_, err := pe.Bot.SendReaction(ctx, pe.ManagementRoom, eventID, "✅")
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to send reaction to confirm successful handling of command")
	}
}

func (pe *PolicyEvaluator) Load(ctx context.Context) {
	err := pe.tryLoad(ctx)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to load initial state")
		pe.sendNotice(ctx, "Failed to load initial state: %v", err)
	} else {
		zerolog.Ctx(ctx).Info().Msg("Loaded initial state")
	}
}

func (pe *PolicyEvaluator) tryLoad(ctx context.Context) error {
	pe.sendNotice(ctx, "Loading initial state...")
	pe.configLock.Lock()
	defer pe.configLock.Unlock()
	start := time.Now()
	state, err := pe.Bot.State(ctx, pe.ManagementRoom)
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
		_, errorMsgs := pe.handleWatchedLists(ctx, evt, true)
		errors = append(errors, errorMsgs...)
	}
	if evt, ok := state[config.StateProtectedRooms][""]; !ok {
		zerolog.Ctx(ctx).Info().Msg("No protected rooms event found in management room")
	} else {
		_, errorMsgs := pe.handleProtectedRooms(ctx, evt, true)
		errors = append(errors, errorMsgs...)
	}
	initDuration := time.Since(start)
	start = time.Now()
	pe.EvaluateAll(ctx)
	evalDuration := time.Since(start)
	pe.protectedRoomsLock.Lock()
	userCount := len(pe.protectedRoomMembers)
	var joinedUserCount int
	for _, rooms := range pe.protectedRoomMembers {
		if len(rooms) > 0 {
			joinedUserCount++
		}
	}
	protectedRoomsCount := len(pe.protectedRooms)
	pe.protectedRoomsLock.Unlock()
	if len(errors) > 0 {
		pe.sendNotice(ctx,
			"Errors occurred during initialization:\n\n%s\n\nProtecting %d rooms with %d users (%d all time) using %d lists.",
			strings.Join(errors, "\n"), protectedRoomsCount, joinedUserCount, userCount, len(pe.GetWatchedLists()))
	} else {
		pe.sendNotice(ctx,
			"Initialization completed successfully (took %s to load data and %s to evaluate rules). "+
				"Protecting %d rooms with %d users (%d all time) using %d lists.",
			initDuration, evalDuration, protectedRoomsCount, joinedUserCount, userCount, len(pe.GetWatchedLists()))
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
