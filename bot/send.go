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
	content := format.RenderMarkdown(message, true, false)
	content.MsgType = event.MsgNotice
	_, err := bot.Client.SendMessageEvent(ctx, roomID, event.EventMessage, &content)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Msg("Failed to send management room message")
	}
}
