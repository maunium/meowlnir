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

// AntiFlood is a protection that redacts and bans users who send too many events in a given time period.
type AntiFlood struct {
	Limit           int              `json:"limit"` // how many events to allow before actioning
	Per             jsontime.Seconds `json:"per"`   // the timespan in which to count events
	MaxInfractions  int              `json:"max_infractions,omitempty"`
	DontTrustServer bool             `json:"dont_trust_server,omitempty"` // if true, always use local time, instead of evt origin
	counts          map[id.UserID]int
	expire          map[id.UserID]time.Time
	countLock       sync.Mutex
}

func (af *AntiFlood) Execute(ctx context.Context, p policyeval.ProtectionParams) (hit bool, err error) {
	if af.Limit <= 0 || p.Evt.StateKey != nil {
		return false, nil // no-op
	}
	af.countLock.Lock()
	defer af.countLock.Unlock()
	if af.counts == nil {
		af.counts = make(map[id.UserID]int)
	}
	if af.expire == nil {
		af.expire = make(map[id.UserID]time.Time)
	}

	// Expire old counts
	now := time.Now()
	origin := time.UnixMilli(p.Evt.Timestamp)
	if !useOrigin(af.DontTrustServer, origin) {
		if !af.DontTrustServer {
			zerolog.Ctx(ctx).Warn().
				Str("protection", "anti_flood").
				Stringer("sender", p.Evt.Sender).
				Stringer("room_id", p.Evt.RoomID).
				Stringer("event_id", p.Evt.ID).
				Time("event_origin", origin).
				Time("current_time", now).
				Msg("event origin time is more than 1 hour in the future; falling back to local time")
		}
		origin = now
	}
	for user, exp := range af.expire {
		if now.After(exp) {
			delete(af.counts, user)
			delete(af.expire, user)
		}
	}

	// Count event
	af.counts[p.Evt.Sender]++
	expire, ok := af.expire[p.Evt.Sender]
	if !ok || expire.Before(origin) {
		// If there isn't already an expiry, or the current expiry is before the event origin, set a new expiry
		expire = origin.Add(af.Per.Duration)
	}
	af.expire[p.Evt.Sender] = expire
	zerolog.Ctx(ctx).Trace().
		Str("protection", "anti_flood").
		Stringer("sender", p.Evt.Sender).
		Stringer("room_id", p.Evt.RoomID).
		Stringer("event_id", p.Evt.ID).
		Int("count", af.counts[p.Evt.Sender]).
		Time("expires", expire).
		Int("infractions", af.counts[p.Evt.Sender]-af.Limit).
		Msg("anti_flood count and expiry updated")

	if af.counts[p.Evt.Sender] > af.Limit {
		hit = true
		infractions := af.counts[p.Evt.Sender] - af.Limit
		// At least one of the patterns matched, redact and notify in the background
		go func() {
			var execErr error
			if !p.Eval.DryRun {
				_, execErr = p.Eval.Bot.RedactEvent(ctx, p.Evt.RoomID, p.Evt.ID, mautrix.ReqRedact{Reason: "flooding"})
			}
			if execErr == nil {
				p.SendNotice(
					ctx,
					fmt.Sprintf(
						"Redacted [this message](%s) from %s in %s for exceeding the flood "+
							"limit of %d events per %s with %d events (%d considered infractions).",
						p.Evt.RoomID.EventURI(p.Evt.ID),
						format.MarkdownMention(p.Evt.Sender),
						format.MarkdownMentionRoomID("", p.Evt.RoomID),
						af.Limit,
						af.Per,
						af.counts[p.Evt.Sender],
						infractions,
					),
				)
			} else {
				zerolog.Ctx(ctx).Err(execErr).Msg("failed to redact message for anti_flood")
			}
		}()
		// If the infractions are over the limit, issue a ban
		if infractions >= af.MaxInfractions {
			go func() {
				var execErr error
				if !p.Eval.DryRun {
					_, execErr = p.Eval.Bot.BanUser(
						ctx,
						p.Evt.RoomID,
						&mautrix.ReqBanUser{
							Reason:              "too many recent events (flooding)",
							UserID:              p.Evt.Sender,
							MSC4293RedactEvents: true,
						},
					)
				}
				if execErr == nil {
					p.SendNotice(
						ctx,
						fmt.Sprintf(
							"Banned %s from %s for exceeding the flood infraction limit of %d infractions.",
							format.MarkdownMention(p.Evt.Sender),
							format.MarkdownMentionRoomID("", p.Evt.RoomID),
							af.MaxInfractions,
						),
					)
				} else {
					zerolog.Ctx(ctx).Err(execErr).Msg("failed to ban user for anti_flood")
				}
			}()
		}
	}
	return hit, nil
}

func init() {
	policyeval.RegisterProtection[AntiFlood]("anti_flood")
}
