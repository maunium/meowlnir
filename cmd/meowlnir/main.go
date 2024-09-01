package main

import (
	"context"
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
	"go.mau.fi/util/exzerolog"
	"go.mau.fi/util/ptr"
	"gopkg.in/yaml.v3"
	flag "maunium.net/go/mauflag"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/sqlstatestore"

	"go.mau.fi/meowlnir/config"
	"go.mau.fi/meowlnir/database"
	"go.mau.fi/meowlnir/policyeval"
	"go.mau.fi/meowlnir/policylist"
	"go.mau.fi/meowlnir/synapsedb"
)

var configPath = flag.MakeFull("c", "config", "Path to the config file", "config.yaml").String()
var noSaveConfig = flag.MakeFull("n", "no-update", "Don't update the config file", "false").Bool()
var version = flag.MakeFull("v", "version", "Print the version and exit", "false").Bool()
var wantHelp, _ = flag.MakeHelpFlag()

type Meowlnir struct {
	Config         *config.Config
	Log            *zerolog.Logger
	DB             *database.Database
	SynapseDB      *synapsedb.SynapseDB
	StateStore     *sqlstatestore.SQLStateStore
	Client         *mautrix.Client
	Crypto         *cryptohelper.CryptoHelper
	AS             *appservice.AppService
	EventProcessor *appservice.EventProcessor

	PolicyStore               *policylist.Store
	EvaluatorLock             sync.RWMutex
	EvaluatorByProtectedRoom  map[id.RoomID]*policyeval.PolicyEvaluator
	EvaluatorByManagementRoom map[id.RoomID]*policyeval.PolicyEvaluator
}

var MinSpecVersion = mautrix.SpecV111

func (m *Meowlnir) Init(ctx context.Context, configPath string, noSaveConfig bool) {
	var err error
	m.Config = loadConfig(configPath, noSaveConfig)
	m.Log, err = m.Config.Logging.Compile()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to configure logger:", err)
		os.Exit(11)
	}
	exzerolog.SetupDefaults(m.Log)
	ctx = m.Log.WithContext(ctx)

	m.Log.Info().
		Str("version", VersionWithCommit).
		Time("built_at", ParsedBuildTime).
		Str("go_version", runtime.Version()).
		Msg("Initializing Meowlnir")
	var mainDB *dbutil.Database
	mainDB, err = dbutil.NewFromConfig("meowlnir", m.Config.Database, dbutil.ZeroLogger(m.Log.With().Str("db_section", "main").Logger()))
	if err != nil {
		m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to connect to Meowlnir database")
		os.Exit(12)
	}
	m.DB = database.New(mainDB)
	var synapseDB *dbutil.Database
	synapseDB, err = dbutil.NewFromConfig("", m.Config.SynapseDB, dbutil.ZeroLogger(m.Log.With().Str("db_section", "synapse").Logger()))
	if err != nil {
		m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to connect to Synapse database")
		os.Exit(12)
	}
	m.SynapseDB = &synapsedb.SynapseDB{DB: synapseDB}
	err = m.SynapseDB.CheckVersion(ctx)
	if err != nil {
		m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to check Synapse database schema version")
		os.Exit(12)
	}

	m.Log.Debug().Msg("Preparing Matrix client")
	m.AS, err = appservice.CreateFull(appservice.CreateOpts{
		Registration: &appservice.Registration{
			ID:                  m.Config.Appservice.ID,
			URL:                 m.Config.Server.Address,
			AppToken:            m.Config.Appservice.ASToken,
			ServerToken:         m.Config.Appservice.HSToken,
			SenderLocalpart:     m.Config.Appservice.Bot.Username,
			RateLimited:         ptr.Ptr(false),
			SoruEphemeralEvents: true,
			EphemeralEvents:     true,
			MSC3202:             true,
		},
		HomeserverDomain: m.Config.Homeserver.Domain,
		HomeserverURL:    m.Config.Homeserver.Address,
		HostConfig: appservice.HostConfig{
			Hostname: m.Config.Server.Hostname,
			Port:     m.Config.Server.Port,
		},
	})
	if err != nil {
		m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to create Matrix appservice")
		os.Exit(13)
	}
	m.AS.Log = m.Log.With().Str("component", "matrix").Logger()
	m.StateStore = sqlstatestore.NewSQLStateStore(mainDB, dbutil.ZeroLogger(m.Log.With().Str("db_section", "matrix_state").Logger()), false)
	m.AS.StateStore = m.StateStore
	m.Client = m.AS.BotClient()
	m.Client.SetAppServiceDeviceID = true

	m.PolicyStore = policylist.NewStore()
	m.EvaluatorByProtectedRoom = make(map[id.RoomID]*policyeval.PolicyEvaluator)
	m.EvaluatorByManagementRoom = make(map[id.RoomID]*policyeval.PolicyEvaluator, len(m.Config.Meowlnir.ManagementRooms))
	for _, roomID := range m.Config.Meowlnir.ManagementRooms {
		m.EvaluatorByManagementRoom[roomID] = policyeval.NewPolicyEvaluator(m.Client, m.PolicyStore, roomID)
	}

	m.Log.Debug().Msg("Preparing crypto helper")
	m.Crypto, err = cryptohelper.NewCryptoHelper(m.Client, []byte(m.Config.Appservice.PickleKey), mainDB)
	if err != nil {
		m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to create crypto helper")
		os.Exit(14)
	}
	m.EventProcessor = appservice.NewEventProcessor(m.AS)
	m.AddEventHandlers()
	m.Crypto.ASEventProcessor = m.EventProcessor
	m.Crypto.DBAccountID = ""
	m.Crypto.LoginAs = &mautrix.ReqLogin{
		Type: mautrix.AuthTypeAppservice,
		Identifier: mautrix.UserIdentifier{
			Type: mautrix.IdentifierTypeUser,
			User: m.Config.Appservice.Bot.Username,
		},
		InitialDeviceDisplayName: "Meowlnir",
	}
	m.AS.StateStore = m.Client.StateStore.(appservice.StateStore)
	m.Client.Crypto = m.Crypto

	m.Log.Info().Msg("Initialization complete")
}

func (m *Meowlnir) ensureBotRegistered(ctx context.Context) {
	err := m.AS.BotIntent().EnsureRegistered(ctx)
	if err == nil {
		return
	}
	if errors.Is(err, mautrix.MUnknownToken) {
		m.Log.WithLevel(zerolog.FatalLevel).Msg("The as_token was not accepted. Is the registration file installed in your homeserver correctly?")
		m.Log.Info().Msg("See https://docs.mau.fi/faq/as-token for more info")
	} else if errors.Is(err, mautrix.MExclusive) {
		m.Log.WithLevel(zerolog.FatalLevel).Msg("The as_token was accepted, but the /register request was not. Are the homeserver domain, bot username and username template in the config correct, and do they match the values in the registration?")
		m.Log.Info().Msg("See https://docs.mau.fi/faq/as-register for more info")
	} else {
		m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to register")
	}
	os.Exit(21)
}

func (m *Meowlnir) Run(ctx context.Context) {
	err := m.StateStore.Upgrade(ctx)
	if err != nil {
		m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to upgrade state store")
		os.Exit(20)
	}
	for {
		resp, err := m.Client.Versions(ctx)
		if err != nil {
			if errors.Is(err, mautrix.MForbidden) {
				m.Log.Debug().Msg("M_FORBIDDEN in /versions, trying to register before retrying")
				m.ensureBotRegistered(ctx)
			}
			m.Log.Err(err).Msg("Failed to connect to homeserver, retrying in 10 seconds...")
			time.Sleep(10 * time.Second)
		} else if !resp.ContainsGreaterOrEqual(MinSpecVersion) {
			m.Log.WithLevel(zerolog.FatalLevel).
				Stringer("minimum_required_spec", MinSpecVersion).
				Stringer("latest_supported_spec", resp.GetLatest()).
				Msg("Homeserver is outdated")
			os.Exit(22)
		} else {
			break
		}
	}
	m.ensureBotRegistered(ctx)

	m.EventProcessor.Start(ctx)
	go m.AS.Start()

	if !m.Config.Appservice.Bot.AvatarURL.IsEmpty() {
		err := m.AS.BotIntent().SetAvatarURL(ctx, m.Config.Appservice.Bot.AvatarURL)
		if err != nil {
			m.Log.Warn().Err(err).Msg("Failed to update bot avatar")
		}
	}
	if m.Config.Appservice.Bot.Displayname != "" {
		err := m.AS.BotIntent().SetDisplayName(ctx, m.Config.Appservice.Bot.Displayname)
		if err != nil {
			m.Log.Warn().Err(err).Msg("Failed to update bot displayname")
		}
	}

	m.Log.Info().Msg("Starting crypto")
	err = m.Crypto.Init(ctx)
	if err != nil {
		m.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to initialize client")
		if strings.Contains(err.Error(), "To upload keys, you must pass device_id when authenticating") {
			m.Log.Info().Msg("Ensure that the msc2409_to_device_messages_enabled, msc3202_device_masquerading and msc3202_transaction_extensions experimental features are enabled")
		}
		os.Exit(23)
	}
	m.ensureCrossSigned(ctx)

	for _, room := range m.EvaluatorByManagementRoom {
		room.Load(ctx)
	}

	<-ctx.Done()
	err = m.DB.Close()
	if err != nil {
		m.Log.Err(err).Msg("Failed to close database")
	}
	err = m.SynapseDB.Close()
	if err != nil {
		m.Log.Err(err).Msg("Failed to close Synapse database")
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
	}
	var m Meowlnir
	ctx, cancel := context.WithCancel(context.Background())
	m.Init(ctx, *configPath, *noSaveConfig)
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
