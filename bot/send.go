package bot

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"
)

func (bot *Bot) SendNotice(ctx context.Context, roomID id.RoomID, message string, args ...any) {
	if len(args) > 0 {
		message = fmt.Sprintf(message, args...)
	}
	bot.SendNoticeOpts(ctx, roomID, message, nil)
}

type SendNoticeOpts struct {
	DisallowMarkdown bool
	AllowHTML        bool
	Mentions         *event.Mentions
	SendAsText       bool
}

func (bot *Bot) SendNoticeOpts(ctx context.Context, roomID id.RoomID, message string, opts *SendNoticeOpts) {
	if opts == nil {
		opts = &SendNoticeOpts{}
	}
	content := format.RenderMarkdown(message, !opts.DisallowMarkdown, opts.AllowHTML)
	if !opts.SendAsText {
		content.MsgType = event.MsgNotice
	}
	if opts.Mentions != nil {
		content.Mentions = opts.Mentions
	}
	_, err := bot.Client.SendMessageEvent(ctx, roomID, event.EventMessage, &content)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Msg("Failed to send management room message")
	}
}
