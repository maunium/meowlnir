//go:build goexperiment.jsonv2

package protections

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"regexp"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"

	"go.mau.fi/meowlnir/policyeval"
)

// BadWords is a simple protection that redacts all messages that have a [formatted] body matching a set of
// regexes.
type BadWords struct {
	Patterns []string `json:"patterns,omitempty"`
	compiled []regexp.Regexp
}

type umBadWords BadWords

func (b *BadWords) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	var alias umBadWords
	if err := json.UnmarshalDecode(dec, &alias); err != nil {
		return err
	}
	*b = BadWords(alias)

	b.compiled = make([]regexp.Regexp, len(b.Patterns))
	// compiling the patterns ahead of time is a performance improvement and also allows for preprocessing.
	for i, pattern := range b.Patterns {
		if !strings.HasPrefix(pattern, "(?i)") {
			// force case-insensitivity
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile bad word pattern %q: %w", pattern, err)
		}
		b.compiled[i] = *re
	}
	return nil
}

func (b *BadWords) Execute(ctx context.Context, p policyeval.ProtectionParams) (hit bool, err error) {
	if len(b.compiled) == 0 || p.Evt.Type != event.EventMessage {
		return false, nil // no-op
	}
	content := p.Evt.Content.AsMessage()

	// Check for substring hits
	var (
		flagged, converted string
	)
	if content.FormattedBody != "" && content.Format == event.FormatHTML {
		converted = format.HTMLToText(content.FormattedBody)
	}
	for _, pattern := range b.compiled {
		if matched := pattern.MatchString(content.Body); matched {
			flagged = pattern.String()
			break
		}
		if matched := pattern.MatchString(converted); matched {
			flagged = pattern.String()
			break
		}
	}

	zerolog.Ctx(ctx).Trace().
		Str("protection", "bad_words").
		Bool("disallowed", hit).
		Stringer("sender", p.Evt.Sender).
		Stringer("room_id", p.Evt.RoomID).
		Stringer("event_id", p.Evt.ID).
		Str("plaintext", content.Body).
		Str("flagged_pattern", flagged).
		Msg("bad_words protection checked")

	if flagged != "" {
		// At least one of the patterns matched, redact and notify in the background
		go func() {
			if p.Policy {
				return
			}
			var execErr error
			if !p.Eval.DryRun {
				_, execErr = p.Eval.Bot.RedactEvent(ctx, p.Evt.RoomID, p.Evt.ID, mautrix.ReqRedact{Reason: "bad words"})
			}
			if execErr == nil {
				p.SendNotice(
					ctx,
					fmt.Sprintf(
						"Redacted [this message](%s) from %s in %s for matching the bad word "+
							"pattern `%s`",
						p.Evt.RoomID.EventURI(p.Evt.ID),
						format.MarkdownMention(p.Evt.Sender),
						format.MarkdownMentionRoomID("", p.Evt.RoomID),
						flagged,
					),
				)
			} else {
				zerolog.Ctx(ctx).Err(execErr).Msg("failed to redact message for bad_words")
			}
		}()
	}
	return flagged != "", nil
}

func init() {
	policyeval.RegisterProtection[BadWords]("bad_words")
}
