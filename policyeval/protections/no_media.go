package protections

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policyeval"
)

// NoMedia is a protection that redacts messages containing media of disallowed types.
type NoMedia struct {
	AllowImages         bool        `json:"allow_images"`           // allow m.image
	AllowVideos         bool        `json:"allow_videos"`           // allow m.video
	AllowAudio          bool        `json:"allow_audio"`            // allow m.audio
	AllowFiles          bool        `json:"allow_files"`            // allow m.file
	AllowStickers       bool        `json:"allow_stickers"`         // allow m.sticker event type
	DenyCustomReactions bool        `json:"deny_custom_reactions"`  // deny m.reaction events with mxc://-prefixed keys
	DenyInlineImages    bool        `json:"deny_inline_images"`     // deny text with mxc:// in the formatted_body
	IgnoreUsers         []id.UserID `json:"ignore_users,omitempty"` // users to ignore for this protection
}

func (nm *NoMedia) Execute(ctx context.Context, p policyeval.ProtectionParams) (hit bool, err error) {
	if p.Evt.Type != event.EventMessage && p.Evt.Type != event.EventSticker && p.Evt.Type != event.EventReaction {
		return false, nil // no-op
	}
	if slices.Contains(nm.IgnoreUsers, p.Evt.Sender) {
		return false, nil // ignored user
	}

	switch p.Evt.Type {
	case event.EventMessage:
		content := p.Evt.Content.AsMessage()
		switch content.MsgType {
		case event.MsgImage:
			hit = !nm.AllowImages
		case event.MsgVideo:
			hit = !nm.AllowVideos
		case event.MsgAudio:
			hit = !nm.AllowAudio
		case event.MsgFile:
			hit = !nm.AllowFiles
		}
		if content.FormattedBody != "" && nm.DenyInlineImages {
			hit = hit || (strings.Contains(content.FormattedBody, "mxc://") &&
				strings.Contains(content.FormattedBody, "<img"))
		}
	case event.EventSticker:
		hit = !nm.AllowStickers
	case event.EventReaction:
		content := p.Evt.Content.AsReaction()
		hit = nm.DenyCustomReactions && strings.HasPrefix(content.RelatesTo.Key, "mxc://")
	}
	if hit {
		displayType := p.Evt.Type.Type
		if p.Evt.Type == event.EventMessage {
			displayType = string(p.Evt.Content.AsMessage().MsgType)
		}
		zerolog.Ctx(ctx).Trace().
			Str("protection", "no_media").
			Str("event_type", displayType).
			Bool("disallowed", hit).
			Stringer("sender", p.Evt.Sender).
			Stringer("room_id", p.Evt.RoomID).
			Stringer("event_id", p.Evt.ID).
			Msg("no_media protection hit")
		// At least one of the patterns matched, redact and notify in the background
		go func() {
			// TODO replace with if policyserver
			if p.Eval.DryRun {
				return
			}
			var execErr error
			if !p.Eval.DryRun {
				_, execErr = p.Eval.Bot.RedactEvent(ctx, p.Evt.RoomID, p.Evt.ID, mautrix.ReqRedact{Reason: "media was not allowed"})
			}
			if execErr == nil {
				p.SendNotice(
					ctx,
					fmt.Sprintf(
						"Redacted [this event (%s)](%s) from %s in %s for containing disallowed media.",
						format.SafeMarkdownCode(displayType),
						p.Evt.RoomID.EventURI(p.Evt.ID, p.Eval.Bot.ServerName),
						format.MarkdownMention(p.Evt.Sender),
						format.MarkdownMentionRoomID("", p.Evt.RoomID),
					),
				)
			} else {
				zerolog.Ctx(ctx).Err(execErr).Msg("failed to redact message for no_media")
			}
		}()
	}
	return hit, nil
}

func init() {
	policyeval.RegisterProtection[NoMedia]("no_media")
}
