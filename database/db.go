package database

import (
	lru "github.com/hashicorp/golang-lru/v2"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exerrors"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/database/upgrades"
)

type Database struct {
	*dbutil.Database
	TakenAction    *TakenActionQuery
	Bot            *BotQuery
	ManagementRoom *ManagementRoomQuery
	PSSignature    *PSSignatureQuery
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
			QueryHelper: dbutil.MakeQueryHelper(db, func(qh *dbutil.QueryHelper[*ManagementRoom]) *ManagementRoom {
				return &ManagementRoom{}
			}),
		},
		PSSignature: &PSSignatureQuery{
			QueryHelper: dbutil.MakeQueryHelperSimple(db, func() *PSSignature {
				return &PSSignature{}
			}),
			cache: exerrors.Must(lru.New[id.EventID, *PSSignature](1024)),
		},
	}
}
