package synapsedb

import (
	"context"

	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
)

type SynapseDB struct {
	DB *dbutil.Database
}

const PreferredVersion = 86

func (s *SynapseDB) CheckVersion(ctx context.Context) error {
	var current, compat int
	err := s.DB.QueryRow(ctx, "SELECT version FROM schema_version").Scan(&current)
	if err != nil {
		return err
	}
	err = s.DB.QueryRow(ctx, "SELECT compat_version FROM schema_compat_version").Scan(&compat)
	if err != nil {
		return err
	}
	if current < PreferredVersion {
		zerolog.Ctx(ctx).Warn().
			Int("preferred_version", PreferredVersion).
			Int("current_version", current).
			Int("current_compat_version", compat).
			Msg("Synapse database schema is older than expected")
	} else if compat > PreferredVersion {
		zerolog.Ctx(ctx).Warn().
			Int("preferred_version", PreferredVersion).
			Int("current_version", current).
			Int("current_compat_version", compat).
			Msg("Synapse database schema is newer than expected")
	}
	return nil
}

func (s *SynapseDB) Close() error {
	return s.DB.Close()
}
