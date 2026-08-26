package upgrades

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"go.mau.fi/util/dbutil"
)

var V04 = dbutil.WrapUpgrade(3, 4, 1, "Mark OTKs as needing repair", dbutil.TxnModeOn, func(ctx context.Context, database *dbutil.Database) error {
	var cryptoTableExists bool
	var err error
	if database.Dialect == dbutil.Postgres {
		err = database.QueryRow(ctx, "SELECT true FROM information_schema.tables WHERE table_schema = current_schema() AND table_name = 'crypto_account'").Scan(&cryptoTableExists)

	} else {
		err = database.QueryRow(ctx, "SELECT true FROM sqlite_master WHERE type = 'table' AND name = 'crypto_account'").Scan(&cryptoTableExists)
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to presence check crypto account table: %w", err)
	}
	_, err = database.Exec(ctx, "CREATE TABLE otks_need_reset(user_id TEXT PRIMARY KEY)")
	if err != nil {
		return err
	}
	if !cryptoTableExists {
		return nil
	}
	_, err = database.Exec(ctx, "INSERT INTO otks_need_reset SELECT DISTINCT account_id FROM crypto_account WHERE shared=TRUE")
	return err
})
