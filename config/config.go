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

	ManagementSecret string `yaml:"management_secret"`
	DataSecret       string `yaml:"data_secret"`
	DryRun           bool   `yaml:"dry_run"`

	ReportRoom          id.RoomID `yaml:"report_room"`
	RoomBanRoom         id.RoomID `yaml:"room_ban_room"`
	LoadAllRoomHashes   bool      `yaml:"load_all_room_hashes"`
	HackyRuleFilter     []string  `yaml:"hacky_rule_filter"`
	HackyRedactPatterns []string  `yaml:"hacky_redact_patterns"`

	AdminTokens map[id.UserID]string `yaml:"admin_tokens"`
}

type PolicyServerConfig struct {
	AlwaysRedact bool `yaml:"always_redact"`
}

type AntispamConfig struct {
	Secret                 string `yaml:"secret"`
	FilterLocalInvites     bool   `yaml:"filter_local_invites"`
	AutoRejectInvitesToken string `yaml:"auto_reject_invites_token"`
}

type EncryptionConfig struct {
	Enable    bool   `yaml:"enable"`
	PickleKey string `yaml:"pickle_key"`
}

type Config struct {
	Homeserver   HomeserverConfig   `yaml:"homeserver"`
	Meowlnir     MeowlnirConfig     `yaml:"meowlnir"`
	Antispam     AntispamConfig     `yaml:"antispam"`
	PolicyServer PolicyServerConfig `yaml:"policy_server"`
	Encryption   EncryptionConfig   `yaml:"encryption"`
	Database     dbutil.Config      `yaml:"database"`
	SynapseDB    dbutil.Config      `yaml:"synapse_db"`
	Logging      zeroconfig.Config  `yaml:"logging"`
}
