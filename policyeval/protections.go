package policyeval

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"sync"
	"time"

	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"
)

var protectionsRegistry map[string]reflect.Type

func init() {
	protectionsRegistry = make(map[string]reflect.Type)
	protectionsRegistry["bad_words"] = reflect.TypeOf(BadWords{})
	protectionsRegistry["max_mentions"] = reflect.TypeOf(MaxMentions{})
}

// Protection is an interface that defines the minimum exposed functionality required to define a protection.
// All protection definitions must implement this interface in order to be used.
type Protection interface {
	// Execute runs the current protection, returning an error if it fails.
	// If Meowlnir is running in a dry context, or the policy server is invoking this protection, the final
	// argument should be true, after which the response will indicate true if an external action should be performed
	// or the event blocked.
	Execute(ctx context.Context, pe *PolicyEvaluator, evt *event.Event, dry bool) (bool, error)
}

// BadWords is a simple protection that redacts all messages that have a [formatted] body matching a set of
// regexes.
type BadWords struct {
	Patterns []string `json:"patterns,omitempty"`
}

func (b *BadWords) Execute(ctx context.Context, pe *PolicyEvaluator, evt *event.Event, dry bool) (hit bool, err error) {
	if len(b.Patterns) == 0 || evt.Type != event.EventMessage {
		return false, nil // no-op
	}
	content := evt.Content.AsMessage()
	combined := content.Body + format.HTMLToText(content.FormattedBody)

	// Check for substring hits
	flagged := ""
	for _, pattern := range b.Patterns {
		if matched, _ := regexp.MatchString(pattern, combined); matched {
			hit = true
			flagged = pattern
			break
		}
	}

	if hit && !dry {
		// At least one of the patterns matched, redact and notify in the background
		go func() {
			_, err := pe.Bot.RedactEvent(ctx, evt.RoomID, evt.ID, mautrix.ReqRedact{Reason: "bad words"})
			if err == nil {
				pe.sendNotice(
					ctx,
					fmt.Sprintf(
						"Redacted [this message](%s) from [%s](%s) in [%s](%s) for matching the bad word pattern `%s`.",
						evt.RoomID.EventURI(evt.ID),
						evt.Sender,
						evt.Sender.URI(),
						evt.RoomID,
						evt.RoomID.URI(),
						flagged,
					),
				)
			} else {
				pe.Bot.Log.Error().Err(err).Msg("failed to redact message for bad_words")
			}
		}()
	}
	return hit, nil
}

type MaxMentions struct {
	Limit          int              `json:"limit"`                     // how many mentions to allow before actioning
	Per            jsontime.Seconds `json:"per"`                       // the timespan in which to count mentions
	MaxInfractions int              `json:"max_infractions,omitempty"` // how many warnings can be given before a ban is issued

	counts    map[id.UserID]int
	expire    map[id.UserID]time.Time
	countLock sync.Mutex
}

func (m *MaxMentions) Execute(ctx context.Context, pe *PolicyEvaluator, evt *event.Event, dry bool) (hit bool, err error) {
	if m.Limit <= 0 {
		pe.Bot.Log.Trace().Msg("max_mentions protection disabled, skipping")
		return false, nil // no-op
	}
	content := evt.Content.AsMessage()
	if content.Mentions == nil || len(content.Mentions.UserIDs) == 0 {
		pe.Bot.Log.Trace().Msg("max_mentions protection no mentions, skipping")
		return false, nil
	}

	m.countLock.Lock()
	defer m.countLock.Unlock()
	if m.counts == nil {
		m.counts = make(map[id.UserID]int)
	}
	if m.expire == nil {
		m.expire = make(map[id.UserID]time.Time)
	}

	// Expire old counts
	now := time.Now()
	for user, exp := range m.expire {
		if now.After(exp) {
			delete(m.counts, user)
			delete(m.expire, user)
		}
	}

	uniqueMentions := make(map[id.UserID]struct{})
	for _, uid := range content.Mentions.UserIDs {
		uniqueMentions[uid] = struct{}{}
	}

	// Count mentions
	m.counts[evt.Sender] += len(uniqueMentions)
	m.expire[evt.Sender] = now.Add(m.Per.Duration)
	if m.counts[evt.Sender] > m.Limit {
		hit = true
		infractions := m.counts[evt.Sender] - m.Limit
		if !dry {
			// At least one of the patterns matched, redact and notify in the background
			go func() {
				_, err := pe.Bot.RedactEvent(ctx, evt.RoomID, evt.ID, mautrix.ReqRedact{Reason: "too many mentions!"})
				if err == nil {
					pe.sendNotice(
						ctx,
						fmt.Sprintf(
							"Redacted [this message](%s) from [%s](%s) in [%s](%s) for exceeding the mention limit "+
								"of %d mentions per %s with %d mentions (%d considered infractions).",
							evt.RoomID.EventURI(evt.ID),
							evt.Sender,
							evt.Sender.URI(),
							evt.RoomID,
							evt.RoomID.URI(),
							m.Limit,
							m.Per.String(),
							m.counts[evt.Sender],
							infractions,
						),
					)
				} else {
					pe.Bot.Log.Error().Err(err).Msg("failed to redact message for max_mentions")
				}
			}()
			// If the infractions are over the limit, issue a ban
			if infractions >= m.MaxInfractions {
				go func() {
					_, err := pe.Bot.BanUser(
						ctx,
						evt.RoomID,
						&mautrix.ReqBanUser{
							Reason:              fmt.Sprintf("%d recent mentions (too many mentions)", m.counts[evt.Sender]),
							UserID:              evt.Sender,
							MSC4293RedactEvents: true,
						},
					)
					if err == nil {
						pe.sendNotice(
							ctx,
							fmt.Sprintf(
								"Banned [%s](%s) from [%s](%s) for exceeding the mention infraction limit of %d infractions.",
								evt.Sender,
								evt.Sender.URI(),
								evt.RoomID,
								evt.RoomID.URI(),
								m.MaxInfractions,
							),
						)
					} else {
						pe.Bot.Log.Error().Err(err).Msg("failed to ban user for max_mentions")
					}
				}()
			}
		}
	}
	pe.Bot.Log.Trace().Bool("hit", hit).Msg("max_mentions protection done")
	return hit, nil
}
