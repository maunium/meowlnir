package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/rs/zerolog"
	up "go.mau.fi/util/configupgrade"
	"go.mau.fi/util/dbutil"
	_ "go.mau.fi/util/dbutil/litestream"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/exslices"
	"go.mau.fi/util/exzerolog"
	"go.mau.fi/util/glob"
	"go.mau.fi/util/ptr"
	"gopkg.in/yaml.v3"
	flag "maunium.net/go/mauflag"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	cryptoupgrade "maunium.net/go/mautrix/crypto/sql_store_upgrade"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/sqlstatestore"

	"go.mau.fi/meowlnir/bot"
	"go.mau.fi/meowlnir/config"
	"go.mau.fi/meowlnir/database"
	"go.mau.fi/meowlnir/policyeval"
	"go.mau.fi/meowlnir/policyeval/roomhash"
	"go.mau.fi/meowlnir/policylist"
	"go.mau.fi/meowlnir/synapsedb"
	"go.mau.fi/meowlnir/util"
)

var configPath = flag.MakeFull("c", "config", "Path to the config file", "config.yaml").String()
var noSaveConfig = flag.MakeFull("n", "no-update", "Don't update the config file", "false").Bool()
var version = flag.MakeFull("v", "version", "Print the version and exit", "false").Bool()
var writeExampleConfig = flag.MakeFull("e", "generate-example-config", "Save the example config to the config path and quit.", "false").Bool()
var wantHelp, _ = flag.MakeHelpFlag()

type Meowlnir struct {
	Config         *config.Config
	Log            *zerolog.Logger
	DB             *database.Database
	SynapseDB      *synapsedb.SynapseDB
	StateStore     *sqlstatestore.SQLStateStore
	CryptoStoreDB  *dbutil.Database
	AS             *appservice.AppService
	EventProcessor *appservice.EventProcessor
	PolicyServer   *policyeval.PolicyServer

	PolicyStore               *policylist.Store
	MapLock                   sync.RWMutex
	Bots                      map[id.UserID]*bot.Bot
	EvaluatorByProtectedRoom  map[id.RoomID]*policyeval.PolicyEvaluator
	EvaluatorByManagementRoom map[id.RoomID]*policyeval.PolicyEvaluator
	HackyAutoRedactPatterns   []glob.Glob

	appservicePingOnce sync.Once

	RoomHashes *roomhash.Map
}

func (m *Meowlnir) loadSecret(secret string) *[32]byte {
	if len(secret) == 0 || (strings.Contains(secret, "disable") && len(secret) < 10) {
		return nil
	}
	if strings.HasPrefix(secret, "sha256:") {
		var decoded []byte
		var err error
		decoded, err = hex.DecodeString(strings.TrimPrefix(secret, "sha256:"))
		if err != nil {
			m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to decode secret hash")
			os.Exit(10)
		} else if len(decoded) != 32 {
			m.Log.WithLevel(zerolog.FatalLevel).Msg("Secret hash is not 32 bytes long")
			os.Exit(10)
		}
		return (*[32]byte)(decoded)
	}
	return ptr.Ptr(util.SHA256String(secret))
}

func (m *Meowlnir) Init(configPath string, noSaveConfig bool) {
	var err error
	m.Config = loadConfig(configPath, noSaveConfig)

	policylist.HackyRuleFilter = m.Config.Meowlnir.HackyRuleFilter
	policylist.HackyRuleFilterHashes = exslices.CastFunc(policylist.HackyRuleFilter, func(s string) [32]byte {
		return util.SHA256String(s)
	})

	m.Log, err = m.Config.Logging.Compile()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to configure logger:", err)
		os.Exit(11)
	}
	exzerolog.SetupDefaults(m.Log)

	m.Log.Info().
		Str("version", VersionWithCommit).
		Time("built_at", ParsedBuildTime).
		Str("go_version", runtime.Version()).
		Msg("Initializing Meowlnir")

	var mainDB, synapseDB *dbutil.Database
	mainDB, err = dbutil.NewFromConfig("meowlnir", m.Config.Database, dbutil.ZeroLogger(m.Log.With().Str("db_section", "main").Logger()))
	if err != nil {
		m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to connect to Meowlnir database")
		os.Exit(12)
	}
	if m.Config.SynapseDB.URI != "" {
		synapseDB, err = dbutil.NewFromConfig("", m.Config.SynapseDB, dbutil.ZeroLogger(m.Log.With().Str("db_section", "synapse").Logger()))
		if err != nil {
			m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to connect to Synapse database")
			os.Exit(12)
		}
	}

	m.RoomHashes = roomhash.NewMap()
	m.DB = database.New(mainDB)
	m.StateStore = sqlstatestore.NewSQLStateStore(mainDB, dbutil.ZeroLogger(m.Log.With().Str("db_section", "matrix_state").Logger()), false)
	if m.Config.Encryption.Enable {
		m.CryptoStoreDB = mainDB.Child(cryptoupgrade.VersionTableName, cryptoupgrade.Table, dbutil.ZeroLogger(m.Log.With().Str("db_section", "crypto").Logger()))
	}
	if synapseDB != nil {
		m.SynapseDB = &synapsedb.SynapseDB{DB: synapseDB}
	}

	m.Log.Debug().Msg("Preparing Matrix client")
	m.AS, err = appservice.CreateFull(appservice.CreateOpts{
		Registration: &appservice.Registration{
			ID:                  m.Config.Meowlnir.ID,
			URL:                 m.Config.Meowlnir.Address,
			AppToken:            m.Config.Meowlnir.ASToken,
			ServerToken:         m.Config.Meowlnir.HSToken,
			RateLimited:         ptr.Ptr(false),
			SoruEphemeralEvents: true,
			EphemeralEvents:     true,
			MSC3202:             true,
			MSC4190:             true,
		},
		HomeserverDomain: m.Config.Homeserver.Domain,
		HomeserverURL:    m.Config.Homeserver.Address,
		HostConfig: appservice.HostConfig{
			Hostname: m.Config.Meowlnir.Hostname,
			Port:     m.Config.Meowlnir.Port,
		},
	})
	if err != nil {
		m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to create Matrix appservice")
		os.Exit(13)
	}
	m.PolicyServer = policyeval.NewPolicyServer(m.Config.Homeserver.Domain)
	m.AS.Log = m.Log.With().Str("component", "matrix").Logger()
	m.AS.StateStore = m.StateStore
	m.EventProcessor = appservice.NewEventProcessor(m.AS)
	m.AddEventHandlers()
	m.AddHTTPEndpoints()

	m.PolicyStore = policylist.NewStore()
	m.Bots = make(map[id.UserID]*bot.Bot)
	m.EvaluatorByProtectedRoom = make(map[id.RoomID]*policyeval.PolicyEvaluator)
	m.EvaluatorByManagementRoom = make(map[id.RoomID]*policyeval.PolicyEvaluator)

	var compiledGlobs []glob.Glob
	for _, pattern := range m.Config.Meowlnir.HackyRedactPatterns {
		compiled := glob.Compile(pattern)
		compiledGlobs = append(compiledGlobs, compiled)
	}
	m.HackyAutoRedactPatterns = compiledGlobs

	m.Log.Info().Msg("Initialization complete")
}

func (m *Meowlnir) claimProtectedRoom(roomID id.RoomID, eval *policyeval.PolicyEvaluator, claim bool) *policyeval.PolicyEvaluator {
	m.MapLock.Lock()
	defer m.MapLock.Unlock()
	_, isManagement := m.EvaluatorByManagementRoom[roomID]
	if isManagement {
		return nil
	}
	if existing, ok := m.EvaluatorByProtectedRoom[roomID]; ok {
		if claim {
			return existing
		}
		if existing == eval {
			delete(m.EvaluatorByProtectedRoom, roomID)
		}
		return nil
	} else if !claim {
		return nil
	}
	m.EvaluatorByProtectedRoom[roomID] = eval
	return eval
}

func (m *Meowlnir) createPuppetClient(userID id.UserID) *mautrix.Client {
	cli := exerrors.Must(m.AS.NewExternalMautrixClient(userID, m.Config.Antispam.AutoRejectInvitesToken, ""))
	cli.SetAppServiceUserID = true
	return cli
}

func (m *Meowlnir) initBot(ctx context.Context, db *database.Bot) *bot.Bot {
	intent := m.AS.Intent(id.NewUserID(db.Username, m.AS.HomeserverDomain))
	m.appservicePingOnce.Do(func() {
		intent.EnsureAppserviceConnection(ctx)
	})
	wrapped := bot.NewBot(
		db, intent, m.Log.With().Str("bot", db.Username).Logger(),
		m.DB, m.EventProcessor, m.CryptoStoreDB, m.Config.Encryption.PickleKey,
		m.Config.Meowlnir.AdminTokens[intent.UserID],
	)
	wrapped.Init(ctx)
	if wrapped.CryptoHelper != nil {
		wrapped.CryptoHelper.CustomPostDecrypt = m.HandleMessage
	}
	m.Bots[wrapped.Client.UserID] = wrapped

	managementRooms, err := m.DB.ManagementRoom.GetAll(ctx, db.Username)
	if err != nil {
		wrapped.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to get management room list")
		os.Exit(15)
	}
	for _, roomID := range managementRooms {
		m.EvaluatorByManagementRoom[roomID] = m.newPolicyEvaluator(wrapped, roomID)
	}
	return wrapped
}

func (m *Meowlnir) newPolicyEvaluator(bot *bot.Bot, roomID id.RoomID) *policyeval.PolicyEvaluator {
	var roomHashes *roomhash.Map
	if m.Config.Meowlnir.RoomBanRoom == roomID {
		roomHashes = m.RoomHashes
	}
	return policyeval.NewPolicyEvaluator(
		bot, m.PolicyStore,
		roomID,
		m.DB,
		m.SynapseDB,
		m.claimProtectedRoom,
		m.createPuppetClient,
		m.Config.Antispam.AutoRejectInvitesToken != "",
		m.Config.Antispam.FilterLocalInvites,
		m.Config.Antispam.NotifyManagementRoom,
		m.Config.Meowlnir.DryRun,
		m.HackyAutoRedactPatterns,
		m.PolicyServer,
		roomHashes,
	)
}

func (m *Meowlnir) loadManagementRoom(ctx context.Context, roomID id.RoomID, bot *bot.Bot) bool {
	m.MapLock.Lock()
	defer m.MapLock.Unlock()
	eval, ok := m.EvaluatorByManagementRoom[roomID]
	if ok {
		if eval.Bot == bot {
			return false
		}
		delete(m.EvaluatorByManagementRoom, roomID)
		for _, room := range m.EvaluatorByProtectedRoom {
			if room == eval {
				delete(m.EvaluatorByProtectedRoom, roomID)
			}
		}
	}
	eval = m.newPolicyEvaluator(bot, roomID)
	m.EvaluatorByManagementRoom[roomID] = eval
	go eval.Load(ctx)
	return true
}

func (m *Meowlnir) Run(ctx context.Context) {
	if m.SynapseDB != nil {
		err := m.SynapseDB.CheckVersion(ctx)
		if err != nil {
			m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to check Synapse database schema version")
			os.Exit(14)
		}
	}
	err := m.DB.Upgrade(ctx)
	if err != nil {
		m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to upgrade main db")
		os.Exit(14)
	}
	err = m.StateStore.Upgrade(ctx)
	if err != nil {
		m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to upgrade state store")
		os.Exit(14)
	}
	if m.CryptoStoreDB != nil {
		err = m.CryptoStoreDB.Upgrade(ctx)
		if err != nil {
			m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to upgrade crypto store")
			os.Exit(14)
		}
	}

	go m.AS.Start()

	bots, err := m.DB.Bot.GetAll(ctx)
	if err != nil {
		m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to get bot list")
		os.Exit(15)
	}
	for _, dbBot := range bots {
		m.initBot(ctx, dbBot)
	}

	m.EventProcessor.Start(ctx)

	var wg sync.WaitGroup
	m.MapLock.Lock()
	wg.Add(len(m.EvaluatorByManagementRoom))
	for _, room := range m.EvaluatorByManagementRoom {
		go func() {
			defer wg.Done()
			room.Load(ctx)
		}()
	}
	m.MapLock.Unlock()
	if m.Config.Meowlnir.RoomBanRoom != "" && m.Config.Meowlnir.LoadAllRoomHashes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.LoadAllRoomHashes(ctx)
		}()
	}
	wg.Wait()

	m.Log.Info().Msg("Startup complete")
	m.AS.Ready = true

	<-ctx.Done()
	err = m.DB.Close()
	if err != nil {
		m.Log.Err(err).Msg("Failed to close database")
	}
	if m.SynapseDB != nil {
		err = m.SynapseDB.Close()
		if err != nil {
			m.Log.Err(err).Msg("Failed to close Synapse database")
		}
	}
}

func (m *Meowlnir) LoadAllRoomHashes(ctx context.Context) {
	if m.SynapseDB == nil {
		m.Log.Warn().Msg("Synapse database not configured, can't load all room hashes")
		return
	}
	start := time.Now()
	rooms := m.SynapseDB.GetAllRooms(ctx)
	count := 0
	err := rooms.Iter(func(roomID id.RoomID) (bool, error) {
		count++
		m.RoomHashes.Put(roomID)
		return true, nil
	})
	dur := time.Since(start)
	if err != nil {
		m.Log.Err(err).Dur("duration", dur).Msg("Failed to read room hashes from synapse database")
	} else {
		m.Log.Info().Dur("duration", dur).Int("count", count).Msg("Read all existing room IDs from synapse database")
	}
}

func loadConfig(path string, noSave bool) *config.Config {
	configData, _, err := up.Do(path, !noSave, config.Upgrader)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to upgrade config:", err)
		os.Exit(10)
	}
	var cfg config.Config
	err = yaml.Unmarshal(configData, &cfg)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to parse config:", err)
		os.Exit(10)
	}
	return &cfg
}

func main() {
	initVersion()
	flag.SetHelpTitles(
		"meowlnir - An opinionated Matrix moderation bot.",
		"meowlnir [-hnve] [-c <path>]",
	)
	err := flag.Parse()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	} else if *wantHelp {
		flag.PrintHelp()
		os.Exit(0)
	} else if *version {
		fmt.Println(VersionDescription)
		os.Exit(0)
	} else if *writeExampleConfig {
		if *configPath != "-" && *configPath != "/dev/stdout" && *configPath != "/dev/stderr" {
			if _, err = os.Stat(*configPath); !errors.Is(err, os.ErrNotExist) {
				_, _ = fmt.Fprintln(os.Stderr, *configPath, "already exists, please remove it if you want to generate a new example")
				os.Exit(1)
			}
		}
		if *configPath == "-" {
			fmt.Print(config.ExampleConfig)
		} else {
			exerrors.PanicIfNotNil(os.WriteFile(*configPath, []byte(config.ExampleConfig), 0600))
			fmt.Println("Wrote example config to", *configPath)
		}
		os.Exit(0)
	}
	var m Meowlnir
	ctx, cancel := context.WithCancel(context.Background())
	m.Init(*configPath, *noSaveConfig)
	ctx = m.Log.WithContext(ctx)
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		cancel()
	}()
	m.Run(ctx)
	m.Log.Info().Msg("Meowlnir stopped")
}
