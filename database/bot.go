package database

import (
	"context"

	"go.mau.fi/util/dbutil"
	"maunium.net/go/mautrix/id"
)

const (
	getAllBotsQuery = `
		SELECT username, displayname, avatar_url
		FROM bot
	`
	insertBotQuery = `
		INSERT INTO bot (username, displayname, avatar_url)
		VALUES ($1, $2, $3)
		ON CONFLICT (username) DO UPDATE
			SET displayname=excluded.displayname, avatar_url=excluded.avatar_url
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
}

func (b *Bot) sqlVariables() []any {
	return []any{b.Username, b.Displayname, &b.AvatarURL}
}

func (b *Bot) Scan(row dbutil.Scannable) (*Bot, error) {
	return dbutil.ValueOrErr(b, row.Scan(&b.Username, &b.Displayname, &b.AvatarURL))
}
