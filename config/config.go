package config

import (
	_ "embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/google/uuid"
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

type MeowlnirConfig struct {
	ID      string `yaml:"id"`
	ASToken string `yaml:"as_token"`
	HSToken string `yaml:"hs_token"`

	Address  string `yaml:"address"`
	Hostname string `yaml:"hostname"`
	Port     uint16 `yaml:"port"`

	ManagementSecret string `yaml:"management_secret"`
	DataSecret       string `yaml:"data_secret"`
	FederationAuth   bool   `yaml:"federation_auth"`
	DryRun           bool   `yaml:"dry_run"`
	Untrusted        bool   `yaml:"untrusted"`

	ReportRoom          id.RoomID `yaml:"report_room"`
	RoomBanRoom         id.RoomID `yaml:"room_ban_room"`
	LoadAllRoomHashes   bool      `yaml:"load_all_room_hashes"`
	HackyRuleFilter     []string  `yaml:"hacky_rule_filter"`
	HackyRedactPatterns []string  `yaml:"hacky_redact_patterns"`

	AdminTokens map[id.UserID]string `yaml:"admin_tokens"`
}

type Meowlnir4AllConfig struct {
	AdminRoom            id.RoomID           `yaml:"admin_room"`
	LocalpartTemplate    *template.Template  `yaml:"-"`
	RawLocalpartTemplate string              `yaml:"localpart_template"`
	DisplayName          string              `yaml:"displayname"`
	AvatarURL            id.ContentURI       `yaml:"-"`
	RawAvatarURL         string              `yaml:"avatar_url"`
	RoomName             string              `yaml:"room_name"`
	DefaultWatchedLists  []WatchedPolicyList `yaml:"default_watched_lists"`
}

type serializableMAC Meowlnir4AllConfig

var m4aFuncs = template.FuncMap{
	"uuidgen": uuid.NewString,
	"randstr": func(n int) string {
		return random.StringCharset(n, "0123456789abcdefghijklmnopqrstuvwxyz")
	},
}

type m4aLocalpartData struct {
	OwnerLocalpart string
	OwnerDomain    string
}

func (mac *Meowlnir4AllConfig) FormatLocalpart(owner id.UserID) (string, error) {
	localpart, domain, err := owner.ParseAndValidateRelaxed()
	if err != nil {
		return "", fmt.Errorf("failed to parse owner user ID: %w", err)
	}
	var sb strings.Builder
	err = mac.LocalpartTemplate.Execute(&sb, m4aLocalpartData{
		OwnerLocalpart: localpart,
		OwnerDomain:    domain,
	})
	return sb.String(), err
}

func (mac *Meowlnir4AllConfig) UnmarshalYAML(node *yaml.Node) error {
	var smac serializableMAC
	err := node.Decode(&smac)
	if err != nil {
		return err
	}
	*mac = (Meowlnir4AllConfig)(smac)
	if mac.RawAvatarURL != "" {
		mac.AvatarURL, err = id.ParseContentURI(mac.RawAvatarURL)
		if err != nil {
			return fmt.Errorf("%w in m4a avatar URL", err)
		}
	}
	mac.LocalpartTemplate, err = template.New("localpart").
		Funcs(m4aFuncs).
		Parse(mac.RawLocalpartTemplate)
	if err != nil {
		return fmt.Errorf("failed to parse m4a localpart template: %w", err)
	}
	return nil
}

type PolicyServerConfig struct {
	AlwaysRedact bool   `yaml:"always_redact"`
	SigningKey   string `yaml:"signing_key"`
}

type AntispamConfig struct {
	Secret                 string `yaml:"secret"`
	FilterLocalInvites     bool   `yaml:"filter_local_invites"`
	AutoRejectInvitesToken string `yaml:"auto_reject_invites_token"`
	NotifyManagementRoom   bool   `yaml:"notify_management_room"`
}

type EncryptionConfig struct {
	Enable    bool   `yaml:"enable"`
	PickleKey string `yaml:"pickle_key"`
}

type Config struct {
	Homeserver   HomeserverConfig   `yaml:"homeserver"`
	Meowlnir     MeowlnirConfig     `yaml:"meowlnir"`
	Meowlnir4All Meowlnir4AllConfig `yaml:"meowlnir4all"`
	Antispam     AntispamConfig     `yaml:"antispam"`
	PolicyServer PolicyServerConfig `yaml:"policy_server"`
	Encryption   EncryptionConfig   `yaml:"encryption"`
	Database     dbutil.Config      `yaml:"database"`
	SynapseDB    dbutil.Config      `yaml:"synapse_db"`
	Logging      zeroconfig.Config  `yaml:"logging"`
}
