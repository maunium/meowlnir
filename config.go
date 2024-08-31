package main

import (
	_ "embed"
	"fmt"
	"os"

	up "go.mau.fi/util/configupgrade"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/random"
	"go.mau.fi/zeroconfig"
	"gopkg.in/yaml.v3"
	"maunium.net/go/mautrix/id"
)

//go:embed example-config.yaml
var ExampleConfig string

type HomeserverConfig struct {
	Address string `yaml:"address"`
	Domain  string `yaml:"domain"`
}

type BotConfig struct {
	Username    string        `yaml:"username"`
	Displayname string        `yaml:"displayname"`
	AvatarURL   id.ContentURI `yaml:"avatar_url"`
}

type AppserviceConfig struct {
	ID        string    `yaml:"id"`
	ASToken   string    `yaml:"as_token"`
	HSToken   string    `yaml:"hs_token"`
	Bot       BotConfig `yaml:"bot"`
	PickleKey string    `yaml:"pickle_key"`
}

type ServerConfig struct {
	Address  string `yaml:"address"`
	Hostname string `yaml:"hostname"`
	Port     uint16 `yaml:"port"`
}

type Config struct {
	Homeserver HomeserverConfig  `yaml:"homeserver"`
	Appservice AppserviceConfig  `yaml:"appservice"`
	Server     ServerConfig      `yaml:"server"`
	Database   dbutil.Config     `yaml:"database"`
	SynapseDB  dbutil.Config     `yaml:"synapse_db"`
	Logging    zeroconfig.Config `yaml:"logging"`
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

	helper.Copy(up.Str, "appservice", "id")
	generateOrCopy(helper, "appservice", "as_token")
	generateOrCopy(helper, "appservice", "hs_token")
	helper.Copy(up.Str, "appservice", "bot", "username")
	helper.Copy(up.Str|up.Null, "appservice", "bot", "displayname")
	helper.Copy(up.Str|up.Null, "appservice", "bot", "avatar_url")
	generateOrCopy(helper, "appservice", "pickle_key")

	helper.Copy(up.Str, "server", "address")
	helper.Copy(up.Str, "server", "hostname")
	helper.Copy(up.Int, "server", "port")

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
	{"appservice"},
	{"server"},
	{"database"},
	{"synapse_db"},
	{"logging"},
}

func loadConfig(path string, noSave bool) *Config {
	configData, _, err := up.Do(path, !noSave, &up.StructUpgrader{
		SimpleUpgrader: upgradeConfig,
		Blocks:         SpacedBlocks,
		Base:           ExampleConfig,
	})
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to upgrade config:", err)
		os.Exit(10)
	}
	var config Config
	err = yaml.Unmarshal(configData, &config)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Failed to parse config:", err)
		os.Exit(10)
	}
	return &config
}
