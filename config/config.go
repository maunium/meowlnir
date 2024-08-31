package config

import (
	_ "embed"

	"go.mau.fi/util/dbutil"
	"go.mau.fi/zeroconfig"
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
