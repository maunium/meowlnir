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
	Address string `yaml:"address" envconfig:"MEOWLNIR_HOMESERVER_ADDRESS"`
	Domain  string `yaml:"domain" envconfig:"MEOWLNIR_HOMESERVER_DOMAIN"`
}

type MeowlnirConfig struct {
	ID      string `yaml:"id" envconfig:"MEOWLNIR_ID"`
	ASToken string `yaml:"as_token" envconfig:"MEOWLNIR_AS_TOKEN"`
	HSToken string `yaml:"hs_token" envconfig:"MEOWLNIR_HS_TOKEN"`

	Address  string `yaml:"address" envconfig:"MEOWLNIR_ADDRESS"`
	Hostname string `yaml:"hostname" envconfig:"MEOWLNIR_HOSTNAME"`
	Port     uint16 `yaml:"port" envconfig:"MEOWLNIR_PORT"`

	ManagementSecret string `yaml:"management_secret" envconfig:"MEOWLNIR_MANAGEMENT_SECRET"`
	DataSecret       string `yaml:"data_secret" envconfig:"MEOWLNIR_DATA_SECRET"`
	DryRun           bool   `yaml:"dry_run" envconfig:"MEOWLNIR_DRY_RUN"`

	ReportRoom          id.RoomID `yaml:"report_room" envconfig:"MEOWLNIR_REPORT_ROOM"`
	RoomBanRoom         id.RoomID `yaml:"room_ban_room" envconfig:"MEOWLNIR_ROOM_BAN_ROOM"`
	LoadAllRoomHashes   bool      `yaml:"load_all_room_hashes" envconfig:"MEOWLNIR_LOAD_ALL_ROOM_HASHES"`
	HackyRuleFilter     []string  `yaml:"hacky_rule_filter" envconfig:"MEOWLNIR_HACKY_RULE_FILTER"`
	HackyRedactPatterns []string  `yaml:"hacky_redact_patterns" envconfig:"MEOWLNIR_HACKY_REDACT_PATTERNS"`

	AdminTokens map[id.UserID]string `yaml:"admin_tokens" envconfig:"MEOWLNIR_ADMIN_TOKENS"`
}

type PolicyServerConfig struct {
	AlwaysRedact bool `yaml:"always_redact" envconfig:"MEOWLNIR_POLICY_SERVER_ALWAYS_REDACT"`
}

type AntispamConfig struct {
	Secret                 string `yaml:"secret" envconfig:"MEOWLNIR_ANTISPAM_SECRET"`
	FilterLocalInvites     bool   `yaml:"filter_local_invites" envconfig:"MEOWLNIR_ANTISPAM_FILTER_LOCAL_INVITES"`
	AutoRejectInvitesToken string `yaml:"auto_reject_invites_token" envconfig:"MEOWLNIR_ANTISPAM_AUTO_REJECT_INVITES_TOKEN"`
}

type EncryptionConfig struct {
	Enable    bool   `yaml:"enable" envconfig:"MEOWLNIR_ENCRYPTION_ENABLE"`
	PickleKey string `yaml:"pickle_key" envconfig:"MEOWLNIR_ENCRYPTION_PICKLE_KEY"`
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
