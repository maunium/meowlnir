package main

import (
	"fmt"
	"runtime"
	"strings"
	"time"

	"maunium.net/go/mautrix"
)

const (
	Name    = "Meowlnir"
	URL     = "https://github.com/maunium/meowlnir"
	Version = "0.4.0"
)

var (
	BuildTime string
	Commit    string
	Tag       string

	ParsedBuildTime    time.Time
	LinkifiedVersion   string
	VersionWithCommit  string
	VersionDescription string
)

func initVersion() {
	Tag = strings.TrimPrefix(Tag, "v")
	LinkifiedVersion = fmt.Sprintf("v%s", Version)
	if Tag != Version {
		suffix := ""
		if !strings.HasSuffix(Version, "+dev") {
			suffix = "+dev"
		}
		if len(Commit) > 8 {
			VersionWithCommit = fmt.Sprintf("%s%s.%s", Version, suffix, Commit[:8])
			LinkifiedVersion = fmt.Sprintf("[%s%s.%s](%s/commit/%s)", Version, suffix, Commit[:8], URL, Commit)
		} else {
			VersionWithCommit = fmt.Sprintf("%s%s.unknown", Version, suffix)
		}
	} else {
		VersionWithCommit = Version
		LinkifiedVersion = fmt.Sprintf("[v%s](%s/releases/v%s)", Version, URL, Tag)
	}
	if BuildTime != "" {
		ParsedBuildTime, _ = time.Parse(time.RFC3339, BuildTime)
	}
	var builtWith string
	if ParsedBuildTime.IsZero() {
		builtWith = runtime.Version()
	} else {
		builtWith = fmt.Sprintf("built at %s with %s", ParsedBuildTime.Format(time.RFC1123), runtime.Version())
	}
	mautrix.DefaultUserAgent = fmt.Sprintf("%s/%s %s", Name, VersionWithCommit, mautrix.DefaultUserAgent)
	VersionDescription = fmt.Sprintf("%s %s (%s)", Name, VersionWithCommit, builtWith)
}
