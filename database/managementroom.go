package database

import (
	"context"

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"
)

const (
	getAllManagementRoomsQuery = `
		SELECT room_id FROM management_room WHERE bot_username=$1;
	`
	putManagementRoomQuery = `
		INSERT INTO management_room (room_id, bot_username)
		VALUES ($1, $2)
		ON CONFLICT (room_id) DO UPDATE
			SET bot_username=excluded.bot_username
	`
)

type ManagementRoomQuery struct {
	*dbutil.Database
}

func (mrq *ManagementRoomQuery) Put(ctx context.Context, roomID id.RoomID, botUsername string) error {
	_, err := mrq.Exec(ctx, putManagementRoomQuery, roomID, botUsername)
	return err
}

var roomIDScanner = dbutil.ConvertRowFn[id.RoomID](dbutil.ScanSingleColumn[id.RoomID])

func (mrq *ManagementRoomQuery) GetAll(ctx context.Context, botUsername string) ([]id.RoomID, error) {
	return roomIDScanner.NewRowIter(mrq.Query(ctx, getAllManagementRoomsQuery, botUsername)).AsList()
}
