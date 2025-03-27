package policyeval

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/bot"
)

func (pe *PolicyEvaluator) isMention(content *event.MessageEventContent) bool {
	if content.Mentions != nil {
		return content.Mentions.Has(pe.Bot.UserID)
	}
	return strings.Contains(content.FormattedBody, pe.Bot.UserID.URI().MatrixToURL()) ||
		strings.Contains(content.FormattedBody, pe.Bot.UserID.String())
}

func (pe *PolicyEvaluator) parseAndQuarantineMedia(ctx context.Context, url any) {
	urlStr, ok := url.(string)
	if !ok {
		return
	}
	parsedURL, _ := id.ParseContentURI(urlStr)
	if parsedURL.IsEmpty() {
		return
	}
	pe.quarantineMedia(ctx, parsedURL)
}

func (pe *PolicyEvaluator) HandleMessage(ctx context.Context, evt *event.Event) {
	msgtype := evt.Content.Raw["msgtype"]
	if msgtype == "m.image" || msgtype == "m.video" || msgtype == "m.audio" {
		go func() {
			pe.parseAndQuarantineMedia(ctx, evt.Content.Raw["url"])
			info, ok := evt.Content.Raw["info"].(map[string]any)
			if ok {
				pe.parseAndQuarantineMedia(ctx, info["thumbnail_url"])
			}
		}()
		_, err := pe.Bot.RedactEvent(ctx, evt.RoomID, evt.ID, mautrix.ReqRedact{
			Reason: "media is not currently allowed here",
		})
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to redact media message")
		} else {
			zerolog.Ctx(ctx).Debug().Stringer("event_id", evt.ID).Msg("Redacted media message")
			pe.sendNotice(
				ctx,
				"Redacted media message from [%s](%s) in [%s](%s)",
				evt.Sender, evt.Sender.URI().MatrixToURL(), evt.RoomID, evt.RoomID.URI().MatrixToURL(),
			)
		}
	}
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
			&bot.SendNoticeOpts{Mentions: &event.Mentions{Room: true}, SendAsText: true},
		)
	}
}
