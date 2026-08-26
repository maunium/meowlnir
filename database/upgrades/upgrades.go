package upgrades

import (
	"embed"

	"go.mau.fi/util/dbutil"
)

var Table = dbutil.BuildUpgradeTable().
	WithFS(rawUpgrades).
	With(upgradeV04).
	Finish()

//go:embed *.sql
var rawUpgrades embed.FS
