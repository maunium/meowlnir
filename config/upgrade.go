package config

import (
	up "go.mau.fi/util/configupgrade"
	"go.mau.fi/util/random"
)

var Upgrader = &up.StructUpgrader{
	SimpleUpgrader: upgradeConfig,
	Blocks:         SpacedBlocks,
	Base:           ExampleConfig,
}

func generateOrCopy(helper up.Helper, path ...string) {
	if secret, ok := helper.Get(up.Str, path...); !ok || secret == "generate" {
		helper.Set(up.Str, random.String(64), path...)
	} else {
		helper.Copy(up.Str, path...)
	}
}

func upgradeConfig(helper up.Helper) {
	helper.Copy(up.Str, "homeserver", "address")
	helper.Copy(up.Str, "homeserver", "domain")

	helper.Copy(up.Str, "meowlnir", "id")
	generateOrCopy(helper, "meowlnir", "as_token")
	generateOrCopy(helper, "meowlnir", "hs_token")
	helper.Copy(up.Str, "meowlnir", "address")
	helper.Copy(up.Str, "meowlnir", "hostname")
	helper.Copy(up.Int, "meowlnir", "port")
	generateOrCopy(helper, "meowlnir", "pickle_key")
	generateOrCopy(helper, "meowlnir", "management_secret")
	helper.Copy(up.Bool, "meowlnir", "dry_run")
	helper.Copy(up.Str|up.Null, "meowlnir", "report_room")

	helper.Copy(up.Str, "database", "type")
	helper.Copy(up.Str, "database", "uri")
	helper.Copy(up.Int, "database", "max_open_conns")
	helper.Copy(up.Int, "database", "max_idle_conns")
	helper.Copy(up.Str|up.Null, "database", "max_conn_idle_time")
	helper.Copy(up.Str|up.Null, "database", "max_conn_lifetime")

	helper.Copy(up.Str, "synapse_db", "type")
	helper.Copy(up.Str, "synapse_db", "uri")
	helper.Copy(up.Int, "synapse_db", "max_open_conns")
	helper.Copy(up.Int, "synapse_db", "max_idle_conns")
	helper.Copy(up.Str|up.Null, "synapse_db", "max_conn_idle_time")
	helper.Copy(up.Str|up.Null, "synapse_db", "max_conn_lifetime")

	helper.Copy(up.Map, "logging")
}

var SpacedBlocks = [][]string{
	{"meowlnir"},
	{"meowlnir", "address"},
	{"meowlnir", "pickle_key"},
	{"database"},
	{"synapse_db"},
	{"logging"},
}
