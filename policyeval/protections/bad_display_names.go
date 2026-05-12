//go:build goexperiment.jsonv2

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

// BadDisplayNames is like BadWords, but kicks users who set display names that match instead.
type BadDisplayNames struct {
	BadWords
}

func (b *BadDisplayNames) Execute(ctx context.Context, p policyeval.ProtectionParams) (bool, error) {
	if p.Evt.Type != event.StateMember || p.Evt.GetStateKey() != p.Evt.Sender.String() {
		return false, nil
	}
	content := p.Evt.Content.AsMember()
	if content.Displayname == "" || content.Membership == event.MembershipLeave {
		return false, nil
	}
	var flagged string
	for _, pattern := range b.compiled {
		if pattern.MatchString(content.Displayname) {
			flagged = pattern.String()
			break
		}
	}
	zerolog.Ctx(ctx).Trace().
		Str("protection", "bad_displaynames").
		Bool("disallowed", flagged != "").
		Stringer("sender", p.Evt.Sender).
		Stringer("room_id", p.Evt.RoomID).
		Stringer("event_id", p.Evt.ID).
		Str("string", flagged).
		Str("flagged_pattern", flagged).
		Msg("bad_displaynames protection checked")
	if flagged != "" {
		go func() {
			var execErr error
			if !p.Eval.DryRun {
				_, execErr = p.Eval.Bot.KickUser(ctx, p.Evt.RoomID, &mautrix.ReqKickUser{
					UserID: p.Evt.Sender,
					Reason: "bad words in display name",
				})
			}
			if execErr == nil {
				p.SendNotice(
					ctx,
					fmt.Sprintf(
						"Kicked %s from %s for matching the bad displayname pattern `%s`: ||%s||.",
						format.MarkdownMention(p.Evt.Sender),
						format.MarkdownMentionRoomID("", p.Evt.RoomID),
						flagged,
						format.SafeMarkdownCode(content.Displayname),
					),
				)
			} else {
				zerolog.Ctx(ctx).Err(execErr).Msg("failed to redact message for bad_displaynames")
			}
		}()
	}
	return flagged != "", nil
}

func init() {
	policyeval.RegisterProtection[BadDisplayNames]("bad_displaynames")
}
