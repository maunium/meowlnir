package bot

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exerrors"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/appservice"
	"maunium.net/go/mautrix/crypto"
	"maunium.net/go/mautrix/crypto/cryptohelper"
	"maunium.net/go/mautrix/id"
	"maunium.net/go/mautrix/synapseadmin"

	"go.mau.fi/meowlnir/database"
)

type Bot struct {
	Meta *database.Bot
	Log  zerolog.Logger
	*mautrix.Client
	Intent         *appservice.IntentAPI
	SynapseAdmin   *synapseadmin.Client
	ServerName     string
	CryptoStore    *crypto.SQLCryptoStore
	CryptoHelper   *cryptohelper.CryptoHelper
	Mach           *crypto.OlmMachine
	eventProcessor *appservice.EventProcessor
	mainDB         *database.Database
}

func NewBot(
	bot *database.Bot,
	intent *appservice.IntentAPI,
	log zerolog.Logger,
	db *database.Database,
	ep *appservice.EventProcessor,
	cryptoStoreDB *dbutil.Database,
	pickleKey string,
) *Bot {
	client := intent.Client
	client.SetAppServiceDeviceID = true
	var helper *cryptohelper.CryptoHelper
	var cryptoStore *crypto.SQLCryptoStore
	if cryptoStoreDB != nil {
		cryptoStore = &crypto.SQLCryptoStore{
			DB:        cryptoStoreDB,
			AccountID: client.UserID.String(),
			PickleKey: []byte(pickleKey),
		}
		cryptoStore.InitFields()
		// NewCryptoHelper only returns errors on invalid parameters
		helper = exerrors.Must(cryptohelper.NewCryptoHelper(client, cryptoStore.PickleKey, cryptoStore))
		helper.DBAccountID = cryptoStore.AccountID
		helper.MSC4190 = true
		helper.LoginAs = &mautrix.ReqLogin{InitialDeviceDisplayName: "Meowlnir"}
		client.Crypto = helper
	}
	return &Bot{
		Meta:           bot,
		Client:         client,
		Intent:         intent,
		Log:            log,
		SynapseAdmin:   &synapseadmin.Client{Client: client},
		ServerName:     client.UserID.Homeserver(),
		CryptoStore:    cryptoStore,
		CryptoHelper:   helper,
		eventProcessor: ep,
		mainDB:         db,
	}
}

var MinSpecVersion = mautrix.SpecV111

func (bot *Bot) Init(ctx context.Context) {
	for {
		resp, err := bot.Client.Versions(ctx)
		if err != nil {
			if errors.Is(err, mautrix.MForbidden) {
				bot.Log.Debug().Msg("M_FORBIDDEN in /versions, trying to register before retrying")
				bot.ensureRegistered(ctx)
			}
			bot.Log.Err(err).Msg("Failed to connect to homeserver, retrying in 10 seconds...")
			time.Sleep(10 * time.Second)
		} else if !resp.ContainsGreaterOrEqual(MinSpecVersion) {
			bot.Log.WithLevel(zerolog.FatalLevel).
				Stringer("minimum_required_spec", MinSpecVersion).
				Stringer("latest_supported_spec", resp.GetLatest()).
				Msg("Homeserver is outdated")
			os.Exit(31)
		} else {
			break
		}
	}
	bot.ensureRegistered(ctx)

	if bot.Meta.Displayname != "" {
		err := bot.Intent.SetDisplayName(ctx, bot.Meta.Displayname)
		if err != nil {
			bot.Log.Err(err).Msg("Failed to set displayname")
		}
	}
	if !bot.Meta.AvatarURL.IsEmpty() {
		err := bot.Intent.SetAvatarURL(ctx, bot.Meta.AvatarURL)
		if err != nil {
			bot.Log.Err(err).Msg("Failed to set avatar")
		}
	}

	if bot.CryptoHelper == nil {
		return
	}

	err := bot.CryptoHelper.Init(ctx)
	if err != nil {
		bot.Log.WithLevel(zerolog.FatalLevel).Err(err).
			Msg("Failed to initialize crypto")
		os.Exit(31)
	}
	bot.Mach = bot.CryptoHelper.Machine()
	bot.Mach.SendKeysMinTrust = id.TrustStateCrossSignedTOFU
	bot.Mach.ShareKeysMinTrust = id.TrustStateCrossSignedTOFU
	bot.eventProcessor.OnDeviceList(bot.Mach.HandleDeviceLists)

	hasKeys, isVerified, err := bot.GetVerificationStatus(ctx)
	if err != nil {
		bot.Log.Err(err).Msg("Failed to check verification status")
	} else if !hasKeys {
		bot.Log.Warn().Msg("No cross-signing keys found")
	} else if !isVerified {
		bot.Log.Warn().Msg("Device is not verified")
	} else {
		bot.Log.Debug().Msg("Device is verified")
	}
}

func (bot *Bot) ensureRegistered(ctx context.Context) {
	err := bot.Intent.EnsureRegistered(ctx)
	if err == nil {
		return
	}
	if errors.Is(err, mautrix.MUnknownToken) {
		bot.Log.WithLevel(zerolog.FatalLevel).Msg("The as_token was not accepted. Is the registration file installed in your homeserver correctly?")
		bot.Log.Info().Msg("See https://docs.mau.fi/faq/as-token for more info")
	} else if errors.Is(err, mautrix.MExclusive) {
		bot.Log.WithLevel(zerolog.FatalLevel).Msg("The as_token was accepted, but the /register request was not. Are the homeserver domain, bot username and username template in the config correct, and do they match the values in the registration?")
		bot.Log.Info().Msg("See https://docs.mau.fi/faq/as-register for more info")
	} else {
		bot.Log.WithLevel(zerolog.FatalLevel).Err(err).Msg("Failed to register")
	}
	os.Exit(30)
}
