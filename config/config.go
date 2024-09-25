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

type MeowlnirConfig struct {
	ID      string `yaml:"id"`
	ASToken string `yaml:"as_token"`
	HSToken string `yaml:"hs_token"`

	Address  string `yaml:"address"`
	Hostname string `yaml:"hostname"`
	Port     uint16 `yaml:"port"`

	PickleKey        string `yaml:"pickle_key"`
	ManagementSecret string `yaml:"management_secret"`
	DryRun           bool   `yaml:"dry_run"`

	ReportRoom id.RoomID `yaml:"report_room"`

	HackyRuleFilter []string `yaml:"hacky_rule_filter"`
}

type Config struct {
	Homeserver HomeserverConfig  `yaml:"homeserver"`
	Meowlnir   MeowlnirConfig    `yaml:"meowlnir"`
	Database   dbutil.Config     `yaml:"database"`
	SynapseDB  dbutil.Config     `yaml:"synapse_db"`
	Logging    zeroconfig.Config `yaml:"logging"`
}
