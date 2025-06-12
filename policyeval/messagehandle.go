package policyeval

import (
	"context"
	"fmt"
	"strings"

	"github.com/rs/zerolog"

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
	if evt.Sender == pe.Bot.UserID {
		return
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

	if pe.protections != nil {
		cfg := pe.protections.Global
		if pe.protections.Overrides != nil {
			override, hasOverride := pe.protections.Overrides[evt.RoomID]
			if hasOverride {
				cfg = override
				zerolog.Ctx(ctx).Trace().Msg("room has override")
			}
		}
		if cfg.NoMedia.Enabled {
			zerolog.Ctx(ctx).Trace().Msg("calling media protection callback")
			MediaProtectionCallback(ctx, pe.Bot.Client, evt, &cfg.NoMedia, false)
		}
		if cfg.MaxMentions != nil && cfg.MaxMentions.Enabled {
			zerolog.Ctx(ctx).Trace().Msg("calling mention protection callback")
			MentionProtectionCallback(ctx, pe, evt, cfg.MaxMentions, false)
		}
	}
}

func (pe *PolicyEvaluator) HandleReaction(ctx context.Context, evt *event.Event) {
	if evt.Sender == pe.Bot.UserID {
		return
	}
	if pe.protections != nil {
		cfg := pe.protections.Global
		override, hasOverride := pe.protections.Overrides[evt.RoomID]
		if hasOverride {
			cfg = override
		}
		if cfg.NoMedia.Enabled {
			MediaProtectionCallback(ctx, pe.Bot.Client, evt, &cfg.NoMedia, false)
		}
	}
	pe.commandProcessor.Process(ctx, evt)
}
