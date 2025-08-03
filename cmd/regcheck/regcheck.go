package main

import (
	"context"
	"encoding/json"
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
	"go.mau.fi/util/exerrors"
	"go.mau.fi/util/exzerolog"
	"go.mau.fi/util/ptr"
	"go.mau.fi/zeroconfig"
	"golang.org/x/sync/semaphore"

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
	srt.Transport = fedTransport
	srt.Dialer = defaultDialer
	fed.HTTP.Transport = srt
}

var log *zerolog.Logger

func main() {
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
			fmt.Println("Skipping invalid server name", s)
			return true
		}
		return false
	})
	fmt.Println("Checking", serverNames)
	var wg sync.WaitGroup
	wg.Add(len(serverNames))
	sema := semaphore.NewWeighted(10)
	out := make([]string, len(serverNames))
	serversByReg := make(map[RegMode][]string)
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
			serversByRegLock.Unlock()
		}()
	}
	wg.Wait()
	for _, result := range out {
		fmt.Println("---------------------------------------------------------------")
		fmt.Println(result)
	}
	for mode, servers := range serversByReg {
		fmt.Println("---------------------------------------------------------------")
		fmt.Println("Servers with", mode, "registration")
		fmt.Println()
		for _, serverName := range servers {
			fmt.Println(serverName)
		}
		fmt.Println()
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
		HomeserverURL: parsedURL,
		Client:        defaultHTTP,
		Log:           log.With().Stringer("homeserver_url", parsedURL).Logger(),
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
	default:
		return fmt.Sprintf("unknown (%d)", rm)
	}
}

const (
	RegDangerouslyOpen RegMode = 2
	RegOpen            RegMode = 1
	RegUnknown         RegMode = 0
	RegClosed          RegMode = -1
)

func checkOpenRegistration(serverName string) (string, RegMode) {
	log := log.With().Str("server_name", serverName).Logger()
	var out strings.Builder
	writeOutput := func(format string, args ...any) {
		_, _ = fmt.Fprintf(&out, format, args...)
		out.WriteByte('\n')
	}
	var errors []string
	addError := func(format string, args ...any) {
		errors = append(errors, fmt.Sprintf(format, args...))
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
		} else if respErr.ErrCode == "M_FORBIDDEN" && strings.Contains(respErr.Err, "disabled") {
			regMode = RegClosed
		} else if respErr.ErrCode == "" {
			regMode = RegOpen
		}
	}
	_ = versions
	if len(errors) > 0 {
		writeOutput("Errors:\n%s", strings.Join(errors, "\n"))
	}
	return out.String(), regMode
}
