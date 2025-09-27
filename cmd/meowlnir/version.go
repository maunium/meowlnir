package main

import (
	"fmt"

	"go.mau.fi/util/progver"
	"maunium.net/go/mautrix"
)

const version = "0.8.0"

var (
	BuildTime string
	Commit    string
	Tag       string
)

var VersionInfo = progver.ProgramVersion{
	Name:        "Meowlnir",
	URL:         "https://github.com/maunium/meowlnir",
	BaseVersion: version,
	SemCalVer:   false,
}.Init(Tag, Commit, BuildTime)

func init() {
	mautrix.DefaultUserAgent = fmt.Sprintf("%s/%s %s", VersionInfo.Name, VersionInfo.FormattedVersion, mautrix.DefaultUserAgent)
}
