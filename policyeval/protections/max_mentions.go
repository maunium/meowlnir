package protections

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policyeval"
)

// MaxMentions is a protection that redacts and bans users who mention too many unique users in a given time period.
type MaxMentions struct {
	Limit            int              `json:"limit"`                        // how many mentions to allow before actioning
	Per              jsontime.Seconds `json:"per"`                          // the timespan in which to count mentions
	MaxInfractions   int              `json:"max_infractions,omitempty"`    // how many warnings can be given before a ban is issued
	DontTrustServer  bool             `json:"dont_trust_server,omitempty"`  // if true, always use local time, instead of evt origin
	MustHaveMentions bool             `json:"must_have_mentions,omitempty"` // if true, require that all m.room.message events have `m.mentions` present
	counts           map[id.UserID]int
	expire           map[id.UserID]time.Time
	countLock        sync.Mutex
}

func (mm *MaxMentions) Execute(ctx context.Context, p policyeval.ProtectionParams) (hit bool, err error) {
	if mm.Limit <= 0 {
		return false, nil // no-op
	}
	content := p.Evt.Content.AsMessage()

	if content.Mentions != nil && len(content.Mentions.UserIDs) == 0 {
		return false, nil
	}

	mm.countLock.Lock()
	defer mm.countLock.Unlock()
	if mm.counts == nil {
		mm.counts = make(map[id.UserID]int)
	}
	if mm.expire == nil {
		mm.expire = make(map[id.UserID]time.Time)
	}

	// Expire old counts
	now := time.Now()
	origin := time.UnixMilli(p.Evt.Timestamp)
	if !useOrigin(mm.DontTrustServer, origin) {
		if !mm.DontTrustServer {
			zerolog.Ctx(ctx).Warn().
				Str("protection", "max_mentions").
				Stringer("sender", p.Evt.Sender).
				Stringer("room_id", p.Evt.RoomID).
				Stringer("event_id", p.Evt.ID).
				Time("event_origin", origin).
				Time("current_time", now).
				Msg("event origin time is more than 1 hour in the future; falling back to local time")
		}
		origin = now
	}
	for user, exp := range mm.expire {
		if now.After(exp) {
			delete(mm.counts, user)
			delete(mm.expire, user)
		}
	}

	uniqueMentions := make(map[id.UserID]struct{})
	if content.Mentions == nil && mm.MustHaveMentions {
		// We can't accurately count mentions here, so we'll give the user a single point instead.
		uniqueMentions["dummy"] = struct{}{}
		hit = true
		go func() {
			var execErr error
			if !p.Eval.DryRun {
				_, execErr = p.Eval.Bot.RedactEvent(ctx, p.Evt.RoomID, p.Evt.ID, mautrix.ReqRedact{
					Reason: "Your client did not include mention metadata. Please use a client that supports intentional mentions.",
				})
			}
			if execErr != nil {
				zerolog.Ctx(ctx).Err(execErr).Msg("failed to redact message for max_mentions")
			}
		}()
	} else {
		for _, uid := range content.Mentions.UserIDs {
			uniqueMentions[uid] = struct{}{}
		}
	}

	// Count mentions
	mm.counts[p.Evt.Sender] += len(uniqueMentions)
	mm.expire[p.Evt.Sender] = origin.Add(mm.Per.Duration)
	zerolog.Ctx(ctx).Trace().
		Str("protection", "max_mentions").
		Stringer("sender", p.Evt.Sender).
		Stringer("room_id", p.Evt.RoomID).
		Stringer("event_id", p.Evt.ID).
		Int("count", mm.counts[p.Evt.Sender]).
		Time("expires", mm.expire[p.Evt.Sender]).
		Msg("max_mentions count and expiry updated")
	if mm.counts[p.Evt.Sender] > mm.Limit {
		hit = true
		infractions := mm.counts[p.Evt.Sender] - mm.Limit
		go func() {
			var execErr error
			if !p.Eval.DryRun {
				_, execErr = p.Eval.Bot.RedactEvent(ctx, p.Evt.RoomID, p.Evt.ID, mautrix.ReqRedact{Reason: "too many mentions"})
			}
			if execErr == nil {
				p.SendNotice(
					ctx,
					fmt.Sprintf(
						"Redacted [this message](%s) from %s in %s for exceeding the mention limit "+
							"of %d mentions per %s, with %d mentions (%d considered infractions).",
						p.Evt.RoomID.EventURI(p.Evt.ID),
						format.MarkdownMention(p.Evt.Sender),
						format.MarkdownMentionRoomID("", p.Evt.RoomID),
						mm.Limit,
						mm.Per,
						mm.counts[p.Evt.Sender],
						infractions,
					),
				)
			} else {
				zerolog.Ctx(ctx).Err(execErr).Msg("failed to redact message for max_mentions")
			}
		}()
		// If the infractions are over the limit, issue a ban
		if infractions >= mm.MaxInfractions {
			go func() {
				var execErr error
				if !p.Eval.DryRun {
					_, execErr = p.Eval.Bot.BanUser(
						ctx,
						p.Evt.RoomID,
						&mautrix.ReqBanUser{
							Reason:              fmt.Sprintf("%d recent mentions (too many mentions)", mm.counts[p.Evt.Sender]),
							UserID:              p.Evt.Sender,
							MSC4293RedactEvents: true,
						},
					)
				}
				if execErr == nil {
					p.SendNotice(
						ctx,
						fmt.Sprintf(
							"Banned %s from %s for exceeding the mention infraction limit of "+
								"%d infractions.",
							format.MarkdownMention(p.Evt.Sender),
							format.MarkdownMentionRoomID("", p.Evt.RoomID),
							mm.MaxInfractions,
						),
					)
				} else {
					zerolog.Ctx(ctx).Err(execErr).Msg("failed to ban user for max_mentions")
				}
			}()
		}
	}
	return hit, nil
}

func init() {
	policyeval.RegisterProtection[MaxMentions]("max_mentions")
}
