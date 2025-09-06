package database

import (
	"context"
	"database/sql"

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"
)

const (
	getAllBotsQuery = `
		SELECT username, displayname, avatar_url, recovery_key
		FROM bot
	`
	insertBotQuery = `
		INSERT INTO bot (username, displayname, avatar_url, recovery_key)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (username) DO UPDATE SET
			displayname=excluded.displayname,
			avatar_url=excluded.avatar_url,
			recovery_key=excluded.recovery_key
	`
)

type BotQuery struct {
	*dbutil.QueryHelper[*Bot]
}

func (bq *BotQuery) Put(ctx context.Context, bot *Bot) error {
	return bq.Exec(ctx, insertBotQuery, bot.sqlVariables()...)
}

func (bq *BotQuery) GetAll(ctx context.Context) ([]*Bot, error) {
	return bq.QueryMany(ctx, getAllBotsQuery)
}

type Bot struct {
	Username    string        `json:"username"`
	Displayname string        `json:"displayname"`
	AvatarURL   id.ContentURI `json:"avatar_url"`
	RecoveryKey string        `json:"-"`
}

func (b *Bot) sqlVariables() []any {
	return []any{b.Username, b.Displayname, &b.AvatarURL, dbutil.StrPtr(b.RecoveryKey)}
}

func (b *Bot) Scan(row dbutil.Scannable) (*Bot, error) {
	var rc sql.NullString
	err := row.Scan(&b.Username, &b.Displayname, &b.AvatarURL, &rc)
	if err != nil {
		return nil, err
	}
	b.RecoveryKey = rc.String
	return b, nil
}
