package protections

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policyeval"
)

// MaxJoinRate is a protection that kicks users that join past a certain threshold, to prevent join floods.
// This can be used to set a limit of, for example, 10 joins a minute, after which users will be kicked.
type MaxJoinRate struct {
	Limit           int              `json:"limit"`                       // how many joins to allow before actioning
	Per             jsontime.Seconds `json:"per"`                         // the timespan in which to count joins
	DontTrustServer bool             `json:"dont_trust_server,omitempty"` // if true, always use local time, instead of evt origin
	counts          map[id.RoomID]int
	expire          map[id.RoomID]time.Time
	countLock       sync.Mutex
}

func (mj *MaxJoinRate) Execute(ctx context.Context, p policyeval.ProtectionParams) (hit bool, err error) {
	if mj.Limit <= 0 || p.Evt.Type != event.StateMember {
		return false, nil
	}
	content := p.Evt.Content.AsMember()
	if !content.Membership.IsInviteOrJoin() { // we only care about invites and joins
		return false, nil
	}
	target := id.UserID(*p.Evt.StateKey)

	mj.countLock.Lock()
	defer mj.countLock.Unlock()
	if mj.counts == nil {
		mj.counts = make(map[id.RoomID]int)
	}
	if mj.expire == nil {
		mj.expire = make(map[id.RoomID]time.Time)
	}

	// Expire old counts
	now := time.Now()
	origin := time.UnixMilli(p.Evt.Timestamp)
	if !useOrigin(mj.DontTrustServer, origin) {
		if !mj.DontTrustServer {
			zerolog.Ctx(ctx).Warn().
				Str("protection", "max_join_rate").
				Stringer("sender", p.Evt.Sender).
				Stringer("room_id", p.Evt.RoomID).
				Stringer("event_id", p.Evt.ID).
				Time("event_origin", origin).
				Time("current_time", now).
				Msg("event origin time is more than 1 hour in the future; falling back to local time")
		}
		origin = now
	}
	for room, exp := range mj.expire {
		if now.After(exp) {
			delete(mj.counts, room)
			delete(mj.expire, room)
		}
	}

	// Increase counts
	mj.counts[p.Evt.RoomID]++
	expires, ok := mj.expire[p.Evt.RoomID]
	if !ok {
		expires = origin.Add(mj.Per.Duration)
	}
	// Unlike MaxMentions, we don't increment the window on each join
	mj.expire[p.Evt.RoomID] = expires
	zerolog.Ctx(ctx).Trace().
		Str("protection", "max_join_rate").
		Stringer("target", target).
		Stringer("room_id", p.Evt.RoomID).
		Stringer("event_id", p.Evt.ID).
		Int("count", mj.counts[p.Evt.RoomID]).
		Time("expires", expires).
		Msg("max_join_rate count and expiry updated")

	if mj.counts[p.Evt.RoomID] > mj.Limit {
		hit = true
		// At least one of the patterns matched, kick in the background
		go func() {
			var execErr error
			if !p.Eval.DryRun {
				_, execErr = p.Eval.Bot.KickUser(ctx, p.Evt.RoomID, &mautrix.ReqKickUser{
					UserID: target,
					Reason: "too many recent joins! try again later.",
				})
			}
			if execErr == nil {
				p.SendNotice(
					ctx,
					fmt.Sprintf(
						"Kicked %s from %s for exceeding the join limit of %d joins per %s, with %d joins.",
						format.MarkdownMention(target),
						format.MarkdownMentionRoomID("", p.Evt.RoomID),
						mj.Limit,
						mj.Per,
						mj.counts[p.Evt.RoomID],
					),
				)
			} else {
				zerolog.Ctx(ctx).Err(execErr).Msg("failed to kick user for max_joins")
			}
		}()
	}
	return hit, nil
}

func init() {
	policyeval.RegisterProtection[MaxJoinRate]("join_rate")
}
