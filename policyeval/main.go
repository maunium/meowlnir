package policyeval

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exsync"
	"go.mau.fi/util/glob"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/commands"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/event/cmdschema"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/bot"
	"go.mau.fi/meowlnir/config"
	"go.mau.fi/meowlnir/database"
	"go.mau.fi/meowlnir/policyeval/roomhash"
	"go.mau.fi/meowlnir/policylist"
	"go.mau.fi/meowlnir/synapsedb"
)

type protectedRoomMeta struct {
	Name     string
	ACL      *event.ServerACLEventContent
	Create   *event.CreateEventContent
	ApplyACL bool
}

type PolicyEvaluator struct {
	Bot       *bot.Bot
	Store     *policylist.Store
	SynapseDB *synapsedb.SynapseDB
	DB        *database.Database
	DryRun    bool

	ManagementRoom    id.RoomID
	RequireEncryption bool
	Admins            *exsync.Set[id.UserID]
	RoomHashes        *roomhash.Map
	Untrusted         bool
	provisionM4A      func(context.Context, id.UserID) (id.UserID, id.RoomID, error)

	commandProcessor *commands.Processor[*PolicyEvaluator]

	watchedListsEvent   *config.WatchedListsEventContent
	watchedListsMap     map[id.RoomID]*config.WatchedPolicyList
	watchedListsList    []id.RoomID
	watchedListsNA      []id.RoomID
	watchedListsForACLs []id.RoomID
	watchedListsLock    sync.RWMutex

	configLock sync.Mutex
	aclLock    sync.Mutex

	aclDeferChan chan struct{}

	claimProtected       func(roomID id.RoomID, eval *PolicyEvaluator, claim bool) *PolicyEvaluator
	protectedRoomsEvent  *config.ProtectedRoomsEventContent
	protectedRooms       map[id.RoomID]*protectedRoomMeta
	wantToProtect        map[id.RoomID]struct{}
	isJoining            map[id.RoomID]struct{}
	protectedRoomMembers map[id.UserID][]id.RoomID
	memberHashes         map[[32]byte]id.UserID
	skipACLForRooms      []id.RoomID
	protectedRoomsLock   sync.RWMutex

	pendingInvites       map[pendingInvite]struct{}
	pendingInvitesLock   sync.Mutex
	AutoRejectInvites    bool
	FilterLocalInvites   bool
	BlockInvitesTo       []id.UserID
	BlockInvitesOverride *exsync.Set[id.UserID]
	AntispamNotifyRoom   bool
	createPuppetClient   func(userID id.UserID) *mautrix.Client
	autoRedactPatterns   []glob.Glob
	policyServer         *PolicyServer
}

func NewPolicyEvaluator(
	bot *bot.Bot,
	store *policylist.Store,
	managementRoom id.RoomID,
	requireEncryption bool,
	untrusted bool,
	provisionM4A func(context.Context, id.UserID) (id.UserID, id.RoomID, error),
	db *database.Database,
	synapseDB *synapsedb.SynapseDB,
	claimProtected func(roomID id.RoomID, eval *PolicyEvaluator, claim bool) *PolicyEvaluator,
	createPuppetClient func(userID id.UserID) *mautrix.Client,
	autoRejectInvites, filterLocalInvites, antispamNotify, dryRun bool,
	blockInvitesTo []id.UserID,
	hackyAutoRedactPatterns []glob.Glob,
	policyServer *PolicyServer,
	roomHashes *roomhash.Map,
) *PolicyEvaluator {
	pe := &PolicyEvaluator{
		Bot:                  bot,
		DB:                   db,
		SynapseDB:            synapseDB,
		Store:                store,
		ManagementRoom:       managementRoom,
		RequireEncryption:    requireEncryption,
		Untrusted:            untrusted,
		provisionM4A:         provisionM4A,
		Admins:               exsync.NewSet[id.UserID](),
		commandProcessor:     commands.NewProcessor[*PolicyEvaluator](bot.Client),
		protectedRoomMembers: make(map[id.UserID][]id.RoomID),
		memberHashes:         make(map[[32]byte]id.UserID),
		watchedListsMap:      make(map[id.RoomID]*config.WatchedPolicyList),
		protectedRooms:       make(map[id.RoomID]*protectedRoomMeta),
		wantToProtect:        make(map[id.RoomID]struct{}),
		isJoining:            make(map[id.RoomID]struct{}),
		aclDeferChan:         make(chan struct{}, 1),
		claimProtected:       claimProtected,
		pendingInvites:       make(map[pendingInvite]struct{}),
		createPuppetClient:   createPuppetClient,
		AutoRejectInvites:    autoRejectInvites,
		FilterLocalInvites:   filterLocalInvites,
		BlockInvitesTo:       blockInvitesTo,
		BlockInvitesOverride: exsync.NewSet[id.UserID](),
		AntispamNotifyRoom:   antispamNotify,
		DryRun:               dryRun,
		autoRedactPatterns:   hackyAutoRedactPatterns,
		policyServer:         policyServer,
		RoomHashes:           roomHashes,
	}
	pe.commandProcessor.LogArgs = true
	pe.commandProcessor.Meta = pe
	pe.commandProcessor.PreValidator = commands.AnyPreValidator[*PolicyEvaluator]{
		commands.ValidatePrefixCommand[*PolicyEvaluator](pe.Bot.UserID.String()),
		commands.ValidatePrefixCommand[*PolicyEvaluator]("!meowlnir"),
		commands.ValidatePrefixSubstring[*PolicyEvaluator]("!"),
	}
	pe.commandProcessor.ReactionCommandPrefix = "/"
	pe.commandProcessor.Register(
		cmdJoin,
		cmdKnock,
		cmdLeave,
		cmdPowerLevel,
		cmdRedact,
		cmdRedactRecent,
		cmdKick,
		cmdBan,
		cmdTakedown,
		cmdRemovePolicy,
		cmdRemoveBan,
		cmdRemoveUnban,
		cmdAddUnban,
		cmdAllowInvite,
		cmdMatch,
		cmdSearch,
		cmdSendAsBot,
		cmdSuspend,
		cmdUnsuspend,
		cmdDeactivate,
		cmdBotProfile,
		cmdRooms,
		cmdProvision,
		cmdProtectRoom,
		cmdUnprotectRoom,
		cmdLists,
		cmdListsSubscribe,
		cmdListsUnsubscribe,
		cmdVersion,
		cmdHelp,
	)
	go pe.aclDeferLoop()
	return pe
}

func (pe *PolicyEvaluator) sendNotice(ctx context.Context, message string, args ...any) id.EventID {
	return pe.Bot.SendNotice(ctx, pe.ManagementRoom, message, args...)
}

func (pe *PolicyEvaluator) sendReactions(ctx context.Context, eventID id.EventID, reactions ...string) {
	if eventID == "" {
		return
	}
	for _, react := range reactions {
		_, err := pe.Bot.SendReaction(ctx, pe.ManagementRoom, eventID, react)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Stringer("event_id", eventID).
				Str("reaction", react).
				Msg("Failed to send reaction")
		}
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
	var pls *event.PowerLevelsEventContent
	var errMsg string
	if evt, ok := state[event.StatePowerLevels][""]; !ok {
		return fmt.Errorf("no power level event found in management room")
	} else if pls, errMsg = pe.handlePowerLevels(ctx, evt); errMsg != "" {
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
	var msg string
	if len(errors) > 0 {
		msg = fmt.Sprintf("Errors occurred during initialization:\n\n%s\n\nProtecting %d rooms with %d users (%d all time) using %d lists.",
			strings.Join(errors, "\n"), protectedRoomsCount, joinedUserCount, userCount, len(pe.GetWatchedLists()))
	} else {
		msg = fmt.Sprintf("Initialization completed successfully (took %s to load data and %s to evaluate rules). "+
			"Protecting %d rooms with %d users (%d all time) using %d lists.",
			initDuration, evalDuration, protectedRoomsCount, joinedUserCount, userCount, len(pe.GetWatchedLists()))
	}
	if pe.policyServer.SigningKey != nil {
		msg += fmt.Sprintf("\n\nPolicy server signatures are enabled with the public key `%s`.", pe.policyServer.SigningKey.Pub)
	}
	if pe.DryRun {
		msg += "\n\n**Dry run mode is enabled, no actions will be taken.**"
	}
	pe.sendNotice(ctx, msg)
	if pls.GetUserLevel(pe.Bot.UserID) >= pls.GetEventLevel(event.StateMSC4391BotCommand) {
		pe.syncCommandDescriptions(ctx, state[event.StateMSC4391BotCommand])
	}
	return nil
}

func (pe *PolicyEvaluator) syncCommandDescriptions(ctx context.Context, state map[string]*event.Event) {
	log := zerolog.Ctx(ctx)
	for _, spec := range pe.commandProcessor.AllSpecs() {
		if err := spec.Validate(); err != nil {
			panic(fmt.Errorf("invalid command spec for command %q: %w", spec.Command, err))
		}
		stateKey := spec.StateKey(pe.Bot.UserID)
		evt := state[stateKey]
		delete(state, stateKey)
		if evt != nil {
			content, _ := evt.Content.Parsed.(*cmdschema.EventContent)
			if evt.Sender == pe.Bot.UserID && spec.Equals(content) {
				continue
			}
		}
		resp, err := pe.Bot.SendStateEvent(ctx, pe.ManagementRoom, event.StateMSC4391BotCommand, stateKey, spec)
		if err != nil {
			log.Err(err).
				Str("command", spec.Command).
				Str("state_key", stateKey).
				Msg("Failed to send bot command state event")
		} else {
			log.Debug().
				Str("command", spec.Command).
				Str("state_key", stateKey).
				Stringer("event_id", resp.EventID).
				Msg("Updated bot command state event")
		}
	}
	for stateKey, evt := range state {
		if len(evt.Content.Raw) == 0 || evt.Sender != pe.Bot.UserID {
			continue
		}
		resp, err := pe.Bot.SendStateEvent(ctx, pe.ManagementRoom, event.StateMSC4391BotCommand, stateKey, struct{}{})
		if err != nil {
			log.Err(err).
				Str("state_key", stateKey).
				Msg("Failed to remove obsolete bot command state event")
		} else {
			log.Debug().
				Str("state_key", stateKey).
				Stringer("event_id", resp.EventID).
				Msg("Removed obsolete bot command state event")
		}
	}
}

func (pe *PolicyEvaluator) handlePowerLevels(ctx context.Context, evt *event.Event) (*event.PowerLevelsEventContent, string) {
	content, ok := evt.Content.Parsed.(*event.PowerLevelsEventContent)
	if !ok {
		return nil, "* Failed to parse power level event"
	}
	err := pe.Bot.Intent.FillPowerLevelCreateEvent(ctx, evt.RoomID, content)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("room_id", evt.RoomID).
			Msg("Failed to get create event for power levels in management room power level handler")
	}
	adminLevel := content.GetEventLevel(config.StateWatchedLists)
	admins := exsync.NewSet[id.UserID]()
	if content.CreateEvent != nil && content.CreateEvent.Content.AsCreate().SupportsCreatorPower() {
		admins.Add(content.CreateEvent.Sender)
		for _, creator := range content.CreateEvent.Content.AsCreate().AdditionalCreators {
			admins.Add(creator)
		}
	}
	for user, level := range content.Users {
		if level >= adminLevel {
			admins.Add(user)
		}
	}
	pe.Admins.ReplaceAll(admins)
	return content, ""
}
