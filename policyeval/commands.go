package policyeval

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

func (pe *PolicyEvaluator) HandleCommand(ctx context.Context, evt *event.Event) {
	fields := strings.Fields(evt.Content.AsMessage().Body)
	cmd := fields[0]
	args := fields[1:]
	zerolog.Ctx(ctx).Info().Str("command", cmd).Msg("Handling command")
	switch strings.ToLower(cmd) {
	case "!join":
		for _, arg := range args {
			pe.Bot.JoinRoom(ctx, arg, "", nil)
		}
	case "!redact":
		pe.RedactUser(ctx, id.UserID(args[0]), strings.Join(args[1:], " "), false)
	case "!match":
		start := time.Now()
		match := pe.Store.MatchUser(nil, id.UserID(args[0]))
		dur := time.Since(start)
		if match != nil {
			eventStrings := make([]string, len(match))
			for i, policy := range match {
				eventStrings[i] = fmt.Sprintf("* [%s](%s) set recommendation `%s` for `%s` at %s for %s",
					policy.Sender, policy.Sender.URI().MatrixToURL(), policy.Recommendation, policy.Entity, time.UnixMilli(policy.Timestamp), policy.Reason)
			}
			pe.sendNotice(ctx, "Matched in %s with recommendations %+v\n\n%s", dur, match.Recommendations(), strings.Join(eventStrings, "\n"))
		} else {
			pe.sendNotice(ctx, "No match in %s", dur.String())
		}
	}
}
