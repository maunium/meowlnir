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

	generateOrCopy(helper, "meowlnir", "management_secret")
	generateOrCopy(helper, "meowlnir", "data_secret")
	helper.Copy(up.Bool, "meowlnir", "dry_run")
	helper.Copy(up.Bool, "meowlnir", "untrusted")
	helper.Copy(up.Str|up.Null, "meowlnir", "report_room")
	helper.Copy(up.Str|up.Null, "meowlnir", "room_ban_room")
	helper.Copy(up.Bool, "meowlnir", "load_all_room_hashes")
	helper.Copy(up.List, "meowlnir", "hacky_rule_filter")
	helper.Copy(up.List, "meowlnir", "hacky_redact_patterns")
	helper.Copy(up.Map, "meowlnir", "admin_tokens")

	if secret, ok := helper.Get(up.Str, "meowlnir", "antispam_secret"); ok && secret != "generate" {
		helper.Set(up.Str, secret, "antispam", "secret")
	} else {
		generateOrCopy(helper, "antispam", "secret")
	}
	helper.Copy(up.Str|up.Null, "antispam", "auto_reject_invites_token")
	helper.Copy(up.Bool, "antispam", "filter_local_invites")
	helper.Copy(up.Bool, "antispam", "notify_management_room")

	helper.Copy(up.Bool, "policy_server", "always_redact")

	if secret, ok := helper.Get(up.Str, "meowlnir", "pickle_key"); ok && secret != "generate" {
		helper.Set(up.Str, secret, "encryption", "pickle_key")
	} else {
		generateOrCopy(helper, "encryption", "pickle_key")
	}
	helper.Copy(up.Bool, "encryption", "enable")

	helper.Copy(up.Str, "database", "type")
	helper.Copy(up.Str, "database", "uri")
	helper.Copy(up.Int, "database", "max_open_conns")
	helper.Copy(up.Int, "database", "max_idle_conns")
	helper.Copy(up.Str|up.Null, "database", "max_conn_idle_time")
	helper.Copy(up.Str|up.Null, "database", "max_conn_lifetime")

	helper.Copy(up.Str|up.Null, "synapse_db", "type")
	helper.Copy(up.Str|up.Null, "synapse_db", "uri")
	helper.Copy(up.Int|up.Null, "synapse_db", "max_open_conns")
	helper.Copy(up.Int|up.Null, "synapse_db", "max_idle_conns")
	helper.Copy(up.Str|up.Null, "synapse_db", "max_conn_idle_time")
	helper.Copy(up.Str|up.Null, "synapse_db", "max_conn_lifetime")

	helper.Copy(up.Map, "logging")
}

var SpacedBlocks = [][]string{
	{"meowlnir"},
	{"meowlnir", "address"},
	{"meowlnir", "management_secret"},
	{"meowlnir", "report_room"},
	{"antispam"},
	{"policy_server"},
	{"encryption"},
	{"database"},
	{"synapse_db"},
	{"logging"},
}
