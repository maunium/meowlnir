package config

import (
	_ "embed"

	"go.mau.fi/util/dbutil"
	"go.mau.fi/zeroconfig"
)

//go:embed example-config.yaml
var ExampleConfig string

type HomeserverConfig struct {
	Address string `yaml:"address"`
	Domain  string `yaml:"domain"`
}

type AppserviceConfig struct {
	ID        string `yaml:"id"`
	ASToken   string `yaml:"as_token"`
	HSToken   string `yaml:"hs_token"`
	PickleKey string `yaml:"pickle_key"`

	ManagementSecret string `yaml:"management_secret"`
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
