package protections

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"

	"go.mau.fi/meowlnir/policyeval"
)

// WellFormedEvent is a protection that redacts messages containing invalid content.
// Currently only applies in the policy server.
type WellFormedEvent struct{}

func (wfe *WellFormedEvent) isWellFormed(p policyeval.ProtectionParams) bool {
	if len(p.Evt.Content.Raw) == 0 {
		// Always allow redacted events
		return true
	} else if p.ParseFailed {
		return false
	}
	// TODO are any type-specific checks necessary beyond struct parsing being successful?
	return true
}

func (wfe *WellFormedEvent) Execute(ctx context.Context, p policyeval.ProtectionParams) (hit bool, err error) {
	hit = !wfe.isWellFormed(p)
	if hit {
		displayType := p.Evt.Type.Type
		if p.Evt.Type == event.EventMessage {
			displayType = string(p.Evt.Content.AsMessage().MsgType)
		}
		zerolog.Ctx(ctx).Trace().
			Str("protection", "well_formed_event").
			Str("event_type", displayType).
			Bool("disallowed", hit).
			Stringer("sender", p.Evt.Sender).
			Stringer("room_id", p.Evt.RoomID).
			Stringer("event_id", p.Evt.ID).
			Msg("well_formed_event protection hit")
		go func() {
			if p.Policy {
				return
			}
			var execErr error
			if !p.Eval.DryRun {
				_, execErr = p.Eval.Bot.RedactEvent(ctx, p.Evt.RoomID, p.Evt.ID, mautrix.ReqRedact{Reason: "bad JSON content"})
			}
			if execErr == nil {
				p.SendNotice(
					ctx,
					fmt.Sprintf(
						"Redacted [this event (%s)](%s) from %s in %s for containing bad JSON.",
						format.SafeMarkdownCode(displayType),
						p.Evt.RoomID.EventURI(p.Evt.ID, p.Eval.Bot.ServerName),
						format.MarkdownMention(p.Evt.Sender),
						format.MarkdownMentionRoomID("", p.Evt.RoomID),
					),
				)
			} else {
				zerolog.Ctx(ctx).Err(execErr).Msg("failed to redact message for well_formed_event")
			}
		}()
	}
	return hit, nil
}

func init() {
	policyeval.RegisterProtection[WellFormedEvent]("well_formed_event", true, 1000)
}
