package policyeval

import (
	"context"
	"fmt"
	"strings"

	"maunium.net/go/mautrix/event"

	"go.mau.fi/meowlnir/bot"
)

func (pe *PolicyEvaluator) isMention(content *event.MessageEventContent) bool {
	if content.Mentions != nil {
		return content.Mentions.Has(pe.Bot.UserID)
	}
	return strings.Contains(content.FormattedBody, pe.Bot.UserID.URI().MatrixToURL()) ||
		strings.Contains(content.FormattedBody, pe.Bot.UserID.String())
}

func (pe *PolicyEvaluator) HandleMessage(ctx context.Context, evt *event.Event) {
	content, ok := evt.Content.Parsed.(*event.MessageEventContent)
	if !ok {
		return
	}
	if pe.isMention(content) {
		pe.Bot.SendNoticeOpts(
			ctx, pe.ManagementRoom,
			fmt.Sprintf(
				`@room [%s](%s) [pinged](%s) the bot in [%s](%s)`,
				evt.Sender, evt.Sender.URI().MatrixToURL(),
				evt.RoomID.EventURI(evt.ID).MatrixToURL(),
				evt.RoomID, evt.RoomID.URI().MatrixToURL(),
			),
			&bot.SendNoticeOpts{Mentions: &event.Mentions{Room: true}},
		)
	}
}
