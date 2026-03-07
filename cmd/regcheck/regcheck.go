package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/tidwall/gjson"
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/exzerolog"
	"go.mau.fi/util/ptr"
	"go.mau.fi/zeroconfig"
	"golang.org/x/sync/semaphore"
	"maunium.net/go/mauflag"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

var ctx context.Context
var defaultDialer = &net.Dialer{Timeout: 10 * time.Second}
var defaultTransport = &http.Transport{
	DialContext:           defaultDialer.DialContext,
	TLSHandshakeTimeout:   10 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
	ForceAttemptHTTP2:     true,
}
var defaultHTTP = &http.Client{Timeout: 2 * time.Minute, Transport: defaultTransport}
var srt = federation.NewServerResolvingTransport(federation.NewInMemoryCache())
var fed = federation.NewClient("", nil, nil)

func init() {
	fedTransport := defaultTransport.Clone()
	fedTransport.DialContext = srt.DialContext
	fed.ResponseSizeLimit = 1024 * 1024
	srt.Transport = fedTransport
	srt.Dialer = defaultDialer
	fed.HTTP.Transport = srt
}

var log *zerolog.Logger

func printlnStderr(args ...any) {
	_, _ = fmt.Fprintln(os.Stderr, args...)
}

var jsonOutput = mauflag.MakeFull("j", "json", "Output summary as JSON instead of text", "false").Bool()
var threads = mauflag.MakeFull("t", "threads", "Number of concurrent threads to use for checking servers", "10").Int64()
var wantHelp, _ = mauflag.MakeHelpFlag()

func main() {
	mauflag.SetHelpTitles("regcheck - Check Matrix servers for open registration", "regcheck [-jh] [-t threads]")
	if err := mauflag.Parse(); err != nil {
		printlnStderr(err)
		return
	} else if *wantHelp {
		mauflag.PrintHelp()
		return
	}
	log = exerrors.Must((&zeroconfig.Config{
		Writers: []zeroconfig.WriterConfig{{
			Type:   zeroconfig.WriterTypeStderr,
			Format: zeroconfig.LogFormatPrettyColored,
		}},
		MinLevel: ptr.Ptr(zerolog.TraceLevel),
	}).Compile())
	exzerolog.SetupDefaults(log)
	ctx = log.WithContext(context.Background())

	stdin := string(exerrors.Must(io.ReadAll(os.Stdin)))
	serverNames := slices.DeleteFunc(strings.Fields(stdin), func(s string) bool {
		if !id.ValidateServerName(s) {
			printlnStderr("Skipping invalid server name", s)
			return true
		}
		return false
	})
	printlnStderr("Checking", serverNames)
	var wg sync.WaitGroup
	wg.Add(len(serverNames))
	sema := semaphore.NewWeighted(*threads)
	out := make([]string, len(serverNames))
	serversByReg := make(map[RegMode][]string)
	regByServer := make(map[string]RegMode)
	var serversByRegLock sync.Mutex
	for i, serverName := range serverNames {
		go func() {
			exerrors.PanicIfNotNil(sema.Acquire(ctx, 1))
			defer sema.Release(1)
			defer wg.Done()
			var regMode RegMode
			out[i], regMode = checkOpenRegistration(serverName)
			serversByRegLock.Lock()
			serversByReg[regMode] = append(serversByReg[regMode], serverName)
			regByServer[serverName] = regMode
			serversByRegLock.Unlock()
		}()
	}
	wg.Wait()
	for _, result := range out {
		printlnStderr("---------------------------------------------------------------")
		printlnStderr(result)
	}
	if *jsonOutput {
		_ = json.NewEncoder(os.Stdout).Encode(regByServer)
	} else {
		for mode, servers := range serversByReg {
			fmt.Println("---------------------------------------------------------------")
			switch mode {
			case RegOAuthOpen:
				fmt.Println("Servers using next-gen auth with account creation allowed")
			case RegOAuth:
				fmt.Println("Servers using next-gen auth")
			default:
				fmt.Println("Servers with", mode, "registration (legacy auth)")
			}
			fmt.Println()
			for _, serverName := range servers {
				fmt.Println(serverName)
			}
			fmt.Println()
		}
	}
}

func newClient(serverURL string) (*mautrix.Client, error) {
	parsedURL, err := url.Parse(serverURL)
	if err != nil {
		return nil, err
	}
	return newClientWithURL(parsedURL), nil
}

func newClientWithURL(parsedURL *url.URL) *mautrix.Client {
	return &mautrix.Client{
		HomeserverURL:     parsedURL,
		Client:            defaultHTTP,
		Log:               log.With().Stringer("homeserver_url", parsedURL).Logger(),
		ResponseSizeLimit: 1024 * 1024,
	}
}

func isUIAOrResponseError(err error) bool {
	if httpErr, ok := err.(mautrix.HTTPError); ok {
		return httpErr.IsStatus(http.StatusUnauthorized) || httpErr.RespError != nil
	}
	return false
}

func guessURLs(serverName string) []*url.URL {
	parsed := id.ParseServerName(serverName)
	if parsed == nil {
		return nil
	}
	guesses := make([]*url.URL, 0, 10)
	// Plain server name
	guesses = append(guesses, &url.URL{Scheme: "https", Host: serverName})
	if !strings.HasPrefix(serverName, "matrix.") && !strings.HasPrefix(serverName, "synapse.") {
		guesses = append(guesses, &url.URL{Scheme: "https", Host: "matrix." + parsed.Host})
		guesses = append(guesses, &url.URL{Scheme: "https", Host: "synapse." + parsed.Host})
		if !strings.HasPrefix(serverName, "chat.") {
			guesses = append(guesses, &url.URL{Scheme: "https", Host: "chat." + parsed.Host})
		}
		if !strings.HasPrefix(serverName, "m.") {
			guesses = append(guesses, &url.URL{Scheme: "https", Host: "m." + parsed.Host})
		}
	}
	if parsed.Host != serverName {
		// If the server name has a port, try 443
		guesses = append(guesses, &url.URL{Scheme: "https", Host: parsed.Host})
	}
	return guesses
}

type RegMode int

func (rm RegMode) String() string {
	switch rm {
	case RegDangerouslyOpen:
		return "dangerously open"
	case RegOpen:
		return "open"
	case RegUnknown:
		return "unknown"
	case RegClosed:
		return "closed"
	case RegOAuth:
		return "oauth"
	case RegOAuthOpen:
		return "oauth open"
	default:
		return fmt.Sprintf("unknown (%d)", rm)
	}
}

func (rm RegMode) MarshalText() ([]byte, error) {
	return []byte(rm.String()), nil
}

const (
	RegDangerouslyOpen RegMode = 100
	RegOpen            RegMode = 50
	RegOAuthOpen       RegMode = 20
	RegOAuth           RegMode = 10
	RegUnknown         RegMode = 0
	RegClosed          RegMode = -10
)

func checkOpenRegistration(serverName string) (string, RegMode) {
	log := log.With().Str("server_name", serverName).Logger()
	var out strings.Builder
	writeOutput := func(format string, args ...any) {
		_, _ = fmt.Fprintf(&out, format, args...)
		out.WriteByte('\n')
	}
	var errorMessages []string
	addError := func(format string, args ...any) {
		errorMessages = append(errorMessages, fmt.Sprintf(format, args...))
	}
	writeOutput("Result for %s:", serverName)
	fedVersion, err := fed.Version(ctx, serverName)
	if err != nil {
		log.Debug().Err(err).Msg("Failed to fetch federation version")
		addError("* Failed to fetch federation version")
	} else {
		writeOutput("Server version: %s %s", fedVersion.Server.Name, fedVersion.Server.Version)
	}
	var cli *mautrix.Client
	var versions *mautrix.RespVersions
	var registerData json.RawMessage
	wkResp, err := mautrix.DiscoverClientAPIWithClient(ctx, defaultHTTP, serverName)
	if wkResp != nil {
		writeOutput("URL from .well-known: %s", wkResp.Homeserver.BaseURL)
	}
	if err != nil {
		log.Err(err).Msg("Failed to fetch .well-known file")
		addError("* Failed to fetch .well-known file")
	} else if wkResp == nil {
		log.Debug().Msg("No .well-known file found")
		addError("* No .well-known file found")
	} else if cli, err = newClient(wkResp.Homeserver.BaseURL); err != nil {
		log.Err(err).Str("homeserver_url", wkResp.Homeserver.BaseURL).Msg("Failed to parse URL from .well-known")
		addError("* .well-known file contained invalid URL")
	} else if versions, err = cli.Versions(ctx); err != nil {
		log.Err(err).Stringer("homeserver_url", cli.HomeserverURL).Msg("Failed to fetch server versions")
		addError("* Failed to fetch server versions with URL from .well-known")
	} else if registerData, err = cli.MakeRequest(ctx, http.MethodPost, cli.BuildClientURL("v3", "register"), nil, nil); err != nil && !isUIAOrResponseError(err) {
		log.Err(err).Stringer("homeserver_url", cli.HomeserverURL).Msg("Failed to fetch registration flows")
		addError("* Failed to fetch registration flows with URL from .well-known")
		registerData = nil
	} else {
		log.Debug().Stringer("homeserver_url", cli.HomeserverURL).Msg("Fetched registration flows")
		writeOutput("Registration flows:\n%s", registerData)
	}
	if registerData == nil {
		guessed := false
		for _, serverURL := range guessURLs(serverName) {
			log.Debug().Stringer("guessed_url", serverURL).Msg("Trying to guess working homeserver URL")
			cli = newClientWithURL(serverURL)
			if versions, err = cli.Versions(ctx); err != nil {
				log.Debug().Err(err).Stringer("guessed_url", serverURL).Msg("Failed to fetch server versions")
			} else if registerData, err = cli.MakeRequest(ctx, http.MethodPost, cli.BuildClientURL("v3", "register"), nil, nil); err != nil && !isUIAOrResponseError(err) {
				log.Debug().Err(err).Stringer("guessed_url", serverURL).Msg("Failed to fetch registration flows")
				addError("* Failed to fetch registration flows with guessed URL %s", serverURL)
			} else {
				writeOutput("Successfully guessed URL: %s", serverURL)
				log.Debug().Stringer("guessed_url", serverURL).Msg("Fetched registration flows")
				writeOutput("Registration flows:\n%s", registerData)
				guessed = true
				break
			}
		}
		if !guessed {
			addError("* Failed to guess working homeserver URL")
		}
	}

	var regMode RegMode
	if registerData != nil {
		var respErr mautrix.RespError
		var uiaResp mautrix.RespUserInteractive
		_ = json.Unmarshal(registerData, &uiaResp)
		_ = json.Unmarshal(registerData, &respErr)
		if slices.ContainsFunc(uiaResp.Flows, func(flow mautrix.UIAFlow) bool {
			return len(flow.Stages) == 1 && flow.Stages[0] == mautrix.AuthTypeDummy
		}) {
			regMode = RegDangerouslyOpen
		} else if errors.Is(respErr, mautrix.MForbidden) {
			regMode = RegClosed
		} else if respErr.ErrCode == "" {
			regMode = RegOpen
		}
	}
	if regMode == RegUnknown || regMode == RegClosed {
		authMetadata, err := cli.MakeRequest(ctx, http.MethodGet, cli.BuildClientURL("v1", "auth_metadata"), nil, nil)
		issuer := gjson.GetBytes(authMetadata, "issuer").Str
		if err == nil && issuer != "" {
			var createSupported bool
			gjson.GetBytes(authMetadata, "prompt_values_supported").ForEach(func(key, value gjson.Result) bool {
				if key.Type == gjson.Number && value.Str == "create" {
					createSupported = true
				}
				return true
			})
			if createSupported {
				regMode = RegOAuthOpen
				writeOutput("OAuth issuer: %s (create prompt value is supported)", issuer)
			} else {
				regMode = RegOAuth
				writeOutput("OAuth issuer: %s", issuer)
			}
			log.Debug().Msg("Found next-gen auth metadata")
		} else if err != nil && !errors.Is(err, mautrix.MUnrecognized) {
			addError("Failed to fetch auth metadata: %v", err)
		}
	}
	_ = versions
	if len(errorMessages) > 0 {
		writeOutput("Errors:\n%s", strings.Join(errorMessages, "\n"))
	}
	return out.String(), regMode
}
