package upgrades

import (
	"context"

	"go.mau.fi/util/dbutil"
)

var upgradeV04 = dbutil.WrapUpgrade(-1, 4, 1, "Mark OTKs as needing repair", dbutil.TxnModeOn, func(ctx context.Context, db *dbutil.Database) error {
	_, err := db.Exec(ctx, `CREATE TABLE otks_need_reset(user_id TEXT PRIMARY KEY);`)
	if err != nil {
		return err
	}
	exists, err := db.TableExists(ctx, "crypto_account")
	if err != nil || !exists {
		return err
	}
	_, err = db.Exec(ctx, `INSERT INTO otks_need_reset SELECT DISTINCT account_id FROM crypto_account WHERE shared=TRUE;`)
	return err
})
