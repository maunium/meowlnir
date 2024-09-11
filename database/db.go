package database

import (
	"go.mau.fi/util/dbutil"

	"go.mau.fi/meowlnir/database/upgrades"
)

type Database struct {
	*dbutil.Database
	TakenAction    *TakenActionQuery
	Bot            *BotQuery
	ManagementRoom *ManagementRoomQuery
}

func New(db *dbutil.Database) *Database {
	db.UpgradeTable = upgrades.Table
	return &Database{
		Database: db,
		TakenAction: &TakenActionQuery{
			QueryHelper: dbutil.MakeQueryHelper(db, func(qh *dbutil.QueryHelper[*TakenAction]) *TakenAction {
				return &TakenAction{}
			}),
		},
		Bot: &BotQuery{
			QueryHelper: dbutil.MakeQueryHelper(db, func(qh *dbutil.QueryHelper[*Bot]) *Bot {
				return &Bot{}
			}),
		},
		ManagementRoom: &ManagementRoomQuery{
			Database: db,
		},
	}
}
