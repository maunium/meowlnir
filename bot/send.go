package bot

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"
)

func (bot *Bot) SendNotice(ctx context.Context, roomID id.RoomID, message string, args ...any) id.EventID {
	if len(args) > 0 {
		message = fmt.Sprintf(message, args...)
	}
	return bot.SendNoticeOpts(ctx, roomID, message, nil)
}

type SendNoticeOpts struct {
	DisallowMarkdown bool
	AllowHTML        bool
	Mentions         *event.Mentions
	SendAsText       bool
	Extra            map[string]any
}

func (bot *Bot) SendNoticeOpts(ctx context.Context, roomID id.RoomID, message string, opts *SendNoticeOpts) id.EventID {
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
	var wrappedContent any = &content
	if opts.Extra != nil {
		wrappedContent = &event.Content{
			Raw:    opts.Extra,
			Parsed: &content,
		}
	}
	resp, err := bot.Client.SendMessageEvent(ctx, roomID, event.EventMessage, wrappedContent)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Msg("Failed to send management room message")
		return ""
	} else {
		return resp.EventID
	}
}
