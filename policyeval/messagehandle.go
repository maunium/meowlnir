package policyeval

import (
	"context"
	"fmt"
	"strings"

	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"

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
				`@room %s [pinged](%s) the bot in %s`,
				format.MarkdownMention(evt.Sender),
				evt.RoomID.EventURI(evt.ID).MatrixToURL(),
				format.MarkdownMentionRoomID("", evt.RoomID),
			),
			&bot.SendNoticeOpts{Mentions: &event.Mentions{Room: true}, SendAsText: true},
		)
	}
	if pe.protections != nil {
		// Don't act if the user is a room mod
		var powerLevels event.PowerLevelsEventContent
		if stateErr := pe.Bot.StateEvent(ctx, evt.RoomID, event.StatePowerLevels, "", &powerLevels); stateErr == nil {
			if powerLevels.GetUserLevel(evt.Sender) > powerLevels.Kick() {
				return
			}
		}
		for _, prot := range pe.protections {
			_, err := prot.Execute(ctx, pe, evt, pe.DryRun)
			if err != nil {
				pe.Bot.Log.Err(err).
					Stringer("room_id", evt.RoomID).
					Stringer("event_id", evt.ID).
					Msg("Failed to execute protection")
			}
			// TODO: short circuit if the event was actioned on?
		}
	}
}
