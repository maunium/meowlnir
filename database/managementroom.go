package database

import (
	"context"

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"
)

const (
	getAllManagementRoomsQuery = `
		SELECT room_id, bot_username, encrypted FROM management_room WHERE bot_username=$1;
	`
	putManagementRoomQuery = `
		INSERT INTO management_room (room_id, bot_username, encrypted)
		VALUES ($1, $2, $3)
		ON CONFLICT (room_id) DO UPDATE SET
			bot_username=excluded.bot_username,
			encrypted=excluded.encrypted;
	`
	deleteManagementRoomQuery = `
		DELETE FROM management_room WHERE room_id=$1
	`
)

type ManagementRoomQuery struct {
	*dbutil.QueryHelper[*ManagementRoom]
}

func (mrq *ManagementRoomQuery) Put(ctx context.Context, mr *ManagementRoom) error {
	return mrq.Exec(ctx, putManagementRoomQuery, mr.sqlVariables()...)
}

func (mrq *ManagementRoomQuery) Delete(ctx context.Context, roomID id.RoomID) error {
	return mrq.Exec(ctx, deleteManagementRoomQuery, roomID)
}

func (mrq *ManagementRoomQuery) GetAll(ctx context.Context, botUsername string) ([]*ManagementRoom, error) {
	return mrq.QueryMany(ctx, getAllManagementRoomsQuery, botUsername)
}

type ManagementRoom struct {
	RoomID      id.RoomID
	BotUsername string
	Encrypted   bool
}

func (m *ManagementRoom) Scan(row dbutil.Scannable) (*ManagementRoom, error) {
	return dbutil.ValueOrErr(m, row.Scan(&m.RoomID, &m.BotUsername, &m.Encrypted))
}

func (m *ManagementRoom) sqlVariables() []any {
	return []any{m.RoomID, m.BotUsername, m.Encrypted}
}
