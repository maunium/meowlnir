package protections

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policyeval"
)

// InsecureRegistration checks server legacy registration requirements when a user joins a room,
// kicking them if they allow registration without email nor captcha, and alerting the management room.
type InsecureRegistration struct {
	// map of servername:insecure
	cache  map[string]bool
	expire map[string]time.Time
	lock   sync.RWMutex
}

func resolveWellKnown(ctx context.Context, client *http.Client, serverName string) string {
	wk, err := mautrix.DiscoverClientAPIWithClient(ctx, client, serverName)
	if err != nil || wk == nil || wk.Homeserver.BaseURL == "" {
		return "https://" + serverName // fallback
	}
	return wk.Homeserver.BaseURL
}

func (ir *InsecureRegistration) Kick(ctx context.Context, p policyeval.ProtectionParams, target id.UserID) {
	var err error
	if !p.Eval.DryRun {
		_, err = p.Eval.Bot.KickUser(ctx, p.Evt.RoomID, &mautrix.ReqKickUser{
			UserID: target,
			Reason: "insecure registration (no email or captcha) on your home server",
		})
	}
	if err == nil {
		p.SendNotice(
			ctx,
			fmt.Sprintf(
				"Kicked %s from %s for joining from a homeserver (%s) that allows insecure registration.",
				format.MarkdownMention(p.Evt.Sender),
				format.MarkdownMentionRoomID("", p.Evt.RoomID),
				target.Homeserver(),
			),
		)
	} else {
		zerolog.Ctx(ctx).Err(err).Msg("failed to kick user for insecure registration")
	}
}

func (ir *InsecureRegistration) Execute(ctx context.Context, p policyeval.ProtectionParams) (hit bool, err error) {
	if ir.expire == nil {
		ir.expire = make(map[string]time.Time)
	}
	if ir.cache == nil {
		ir.cache = make(map[string]bool)
	}
	if p.Evt.Type != event.StateMember {
		return false, nil // no-op
	}
	content := p.Evt.Content.AsMember()
	if !content.Membership.IsInviteOrJoin() { // we only care about invites and joins
		return false, nil
	}

	// Check when the last lookup for this server name was
	target := id.UserID(*p.Evt.StateKey)
	hs := target.Homeserver()
	ir.lock.RLock()
	cached, ok := ir.expire[hs]
	result, hasResult := ir.cache[hs]
	ir.lock.RUnlock()
	if ok && hasResult {
		// If the result is true (insecure) and less than 5 minutes old, it is fresh.
		// Secure results are cached for longer since they're less likely to be invalid.
		if (result && time.Since(cached) < 5*time.Minute) || (!result && time.Since(cached) < time.Hour) {
			if result {
				// Kick user and alert the management room
				go ir.Kick(ctx, p, target)
			}
			return result, nil // recently checked, skip
		}
		ir.lock.Lock()
		delete(ir.cache, hs)
		delete(ir.expire, hs)
		ir.lock.Unlock()
	}

	// Not recently checked, do a lookup
	ir.lock.Lock()
	defer func() {
		// Cache the result
		if err == nil {
			ir.cache[hs] = hit
			ir.expire[hs] = time.Now()
		}
		ir.lock.Unlock()
	}()
	zerolog.Ctx(ctx).Trace().Stringer("user_id", target).Msg("performing insecure registration check")
	baseUrl := resolveWellKnown(ctx, p.Eval.Bot.Client.Client, hs)
	client, err := mautrix.NewClient(baseUrl, "", "")
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Str("homeserver", hs).Msg("failed to create client for insecure registration check")
		return false, err
	}
	_, flows, err := client.Register(ctx, &mautrix.ReqRegister{})
	zerolog.Ctx(ctx).Trace().Stringer("user_id", target).Err(err).Msg("finished insecure registration check")
	if err != nil {
		if errors.Is(err, mautrix.MForbidden) || errors.Is(err, mautrix.MNotFound) {
			// Registration is disabled or handled externally
			zerolog.Ctx(ctx).Trace().Stringer("user_id", target).Msg("homeserver forbids registration.")
			return false, nil
		}
		zerolog.Ctx(ctx).Err(err).Str("homeserver", hs).Msg("failed to query registration flows for insecure registration check")
		return false, err
	}

	hit = flows.HasSingleStageFlow(mautrix.AuthTypeDummy)
	zerolog.Ctx(ctx).Trace().
		Str("homeserver", hs).
		Any("flows", flows.Flows).
		Bool("dangerous", hit).
		Msg("server has registration enabled")
	if hit {
		// Kick user and alert the management room
		go ir.Kick(ctx, p, target)
	}
	return hit, nil
}

func init() {
	policyeval.RegisterProtection[InsecureRegistration]("insecure_registration")
}
