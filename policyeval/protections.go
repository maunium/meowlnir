package policyeval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"strings"
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
	protectionsRegistry["join_rate"] = reflect.TypeOf(MaxJoinRate{})
	protectionsRegistry["no_media"] = reflect.TypeOf(NoMedia{})
	protectionsRegistry["insecure_registration"] = reflect.TypeOf(InsecureRegistration{})
	protectionsRegistry["anti_flood"] = reflect.TypeOf(AntiFlood{})
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
	compiled []regexp.Regexp
}

func (b *BadWords) UnmarshalJSON(data []byte) error {
	type badWordsAlias BadWords
	var alias badWordsAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*b = BadWords(alias)

	b.compiled = make([]regexp.Regexp, 0, len(b.Patterns))
	// compiling the patterns ahead of time is a performance improvement and also allows for preprocessing.
	for _, pattern := range b.Patterns {
		if !strings.HasPrefix(pattern, "(?i)") {
			// force case-insensitivity
			pattern = "(?i)" + pattern
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("failed to compile bad word pattern %q: %w", pattern, err)
		}
		b.compiled = append(b.compiled, *re)
	}
	return nil
}

func (b *BadWords) Execute(ctx context.Context, pe *PolicyEvaluator, evt *event.Event, dry bool) (hit bool, err error) {
	if len(b.compiled) == 0 || evt.Type != event.EventMessage {
		return false, nil // no-op
	}
	content := evt.Content.AsMessage()
	combined := content.Body + format.HTMLToText(content.FormattedBody)

	// Check for substring hits
	flagged := ""
	for _, pattern := range b.compiled {
		if matched := pattern.MatchString(combined); matched {
			hit = true
			flagged = pattern.String()
			break
		}
	}

	pe.Bot.Log.Trace().
		Str("protection", "bad_words").
		Bool("disallowed", hit).
		Stringer("sender", evt.Sender).
		Stringer("room_id", evt.RoomID).
		Stringer("event_id", evt.ID).
		Str("string", combined).
		Str("flagged_pattern", flagged).
		Msg("bad_words protection checked")

	if hit {
		// At least one of the patterns matched, redact and notify in the background
		go func() {
			var execErr error
			if !dry {
				_, execErr = pe.Bot.RedactEvent(ctx, evt.RoomID, evt.ID, mautrix.ReqRedact{Reason: "bad words"})
			}
			if execErr == nil {
				pe.sendNotice(
					ctx,
					fmt.Sprintf(
						"Redacted [this message](%s) from [%s](%s) in [%s](%s) for matching the bad word "+
							"pattern `%s`.",
						evt.RoomID.EventURI(evt.ID),
						evt.Sender,
						evt.Sender.URI(),
						evt.RoomID,
						evt.RoomID.URI(),
						flagged,
					),
				)
			} else {
				pe.Bot.Log.Err(execErr).Msg("failed to redact message for bad_words")
			}
		}()
	}
	return hit, nil
}

// MaxMentions is a protection that redacts and bans users who mention too many unique users in a given time period.
type MaxMentions struct {
	Limit          int              `json:"limit"`                     // how many mentions to allow before actioning
	Per            jsontime.Seconds `json:"per"`                       // the timespan in which to count mentions
	MaxInfractions int              `json:"max_infractions,omitempty"` // how many warnings can be given before a ban is issued
	TrustServer    bool             `json:"trust_server,omitempty"`    // if false, use local time, instead of evt origin
	counts         map[id.UserID]int
	expire         map[id.UserID]time.Time
	countLock      sync.Mutex
}

func (m *MaxMentions) Execute(ctx context.Context, pe *PolicyEvaluator, evt *event.Event, dry bool) (hit bool, err error) {
	if m.Limit <= 0 {
		return false, nil // no-op
	}
	content := evt.Content.AsMessage()
	if content.Mentions == nil || len(content.Mentions.UserIDs) == 0 {
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
	origin := time.UnixMilli(evt.Timestamp)
	if !m.TrustServer || origin.After(now.Add(1*time.Hour)) {
		if m.TrustServer {
			pe.Bot.Log.Warn().
				Str("protection", "max_mentions").
				Stringer("sender", evt.Sender).
				Stringer("room_id", evt.RoomID).
				Stringer("event_id", evt.ID).
				Time("event_origin", origin).
				Time("current_time", now).
				Msg("event origin time is more than 1 hour in the future; falling back to local time")
		}
		origin = now
	}
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
	m.expire[evt.Sender] = origin.Add(m.Per.Duration)
	pe.Bot.Log.Trace().
		Str("protection", "max_mentions").
		Stringer("sender", evt.Sender).
		Stringer("room_id", evt.RoomID).
		Stringer("event_id", evt.ID).
		Int("count", m.counts[evt.Sender]).
		Time("expires", m.expire[evt.Sender]).
		Msg("max_mentions count and expiry updated")
	if m.counts[evt.Sender] > m.Limit {
		hit = true
		infractions := m.counts[evt.Sender] - m.Limit
		go func() {
			var execErr error
			if !dry {
				_, execErr = pe.Bot.RedactEvent(ctx, evt.RoomID, evt.ID, mautrix.ReqRedact{Reason: "too many mentions"})
			}
			if execErr == nil {
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
				pe.Bot.Log.Err(execErr).Msg("failed to redact message for max_mentions")
			}
		}()
		// If the infractions are over the limit, issue a ban
		if infractions >= m.MaxInfractions {
			go func() {
				var execErr error
				if !dry {
					_, execErr = pe.Bot.BanUser(
						ctx,
						evt.RoomID,
						&mautrix.ReqBanUser{
							Reason:              fmt.Sprintf("%d recent mentions (too many mentions)", m.counts[evt.Sender]),
							UserID:              evt.Sender,
							MSC4293RedactEvents: true,
						},
					)
				}
				if execErr == nil {
					pe.sendNotice(
						ctx,
						fmt.Sprintf(
							"Banned [%s](%s) from [%s](%s) for exceeding the mention infraction limit of "+
								"%d infractions.",
							evt.Sender,
							evt.Sender.URI(),
							evt.RoomID,
							evt.RoomID.URI(),
							m.MaxInfractions,
						),
					)
				} else {
					pe.Bot.Log.Err(execErr).Msg("failed to ban user for max_mentions")
				}
			}()
		}
	}
	return hit, nil
}

// MaxJoinRate is a protection that kicks users that join past a certain threshold, to prevent join floods.
// This can be used to set a limit of, for example, 10 joins a minute, after which users will be kicked.
type MaxJoinRate struct {
	Limit       int              `json:"limit"`                  // how many joins to allow before actioning
	Per         jsontime.Seconds `json:"per"`                    // the timespan in which to count joins
	TrustServer bool             `json:"trust_server,omitempty"` // if false, use local time, instead of evt origin
	counts      map[id.RoomID]int
	expire      map[id.RoomID]time.Time
	countLock   sync.Mutex
}

func (m *MaxJoinRate) Execute(ctx context.Context, pe *PolicyEvaluator, evt *event.Event, dry bool) (hit bool, err error) {
	if m.Limit <= 0 || evt.Type != event.StateMember {
		return false, nil
	}
	content := evt.Content.AsMember()
	if !content.Membership.IsInviteOrJoin() { // we only care about invites and joins
		return false, nil
	}
	target := id.UserID(*evt.StateKey)

	m.countLock.Lock()
	defer m.countLock.Unlock()
	if m.counts == nil {
		m.counts = make(map[id.RoomID]int)
	}
	if m.expire == nil {
		m.expire = make(map[id.RoomID]time.Time)
	}

	// Expire old counts
	now := time.Now()
	origin := time.UnixMilli(evt.Timestamp)
	if !m.TrustServer || origin.After(now.Add(1*time.Hour)) {
		if m.TrustServer {
			pe.Bot.Log.Warn().
				Str("protection", "max_join_rate").
				Stringer("sender", evt.Sender).
				Stringer("room_id", evt.RoomID).
				Stringer("event_id", evt.ID).
				Time("event_origin", origin).
				Time("current_time", now).
				Msg("event origin time is more than 1 hour in the future; falling back to local time")
		}
		origin = now
	}
	for room, exp := range m.expire {
		if now.After(exp) {
			delete(m.counts, room)
			delete(m.expire, room)
		}
	}

	// Increase counts
	m.counts[evt.RoomID]++
	expires, ok := m.expire[evt.RoomID]
	if !ok {
		expires = origin.Add(m.Per.Duration)
	}
	// Unlike MaxMentions, we don't increment the window on each join
	m.expire[evt.RoomID] = expires
	pe.Bot.Log.Trace().
		Str("protection", "max_join_rate").
		Stringer("target", target).
		Stringer("room_id", evt.RoomID).
		Stringer("event_id", evt.ID).
		Int("count", m.counts[evt.RoomID]).
		Time("expires", expires).
		Msg("max_join_rate count and expiry updated")

	if m.counts[evt.RoomID] > m.Limit {
		hit = true
		// At least one of the patterns matched, kick in the background
		go func() {
			var execErr error
			if !dry {
				_, execErr = pe.Bot.KickUser(ctx, evt.RoomID, &mautrix.ReqKickUser{
					UserID: target,
					Reason: "too many recent joins! try again later.",
				})
			}
			if execErr == nil {
				pe.sendNotice(
					ctx,
					fmt.Sprintf(
						"Kicked [%s](%s) from [%s](%s) for exceeding the join limit of %d joins per %s, with %d joins.",
						target,
						target.URI(),
						evt.RoomID,
						evt.RoomID.URI(),
						m.Limit,
						m.Per.String(),
						m.counts[evt.RoomID],
					),
				)
			} else {
				pe.Bot.Log.Err(execErr).Msg("failed to kick user for max_joins")
			}
		}()
	}
	return hit, nil
}

// NoMedia is a protection that redacts messages containing media of disallowed types.
type NoMedia struct {
	AllowImages         bool `json:"allow_images"`          // allow m.image
	AllowVideos         bool `json:"allow_videos"`          // allow m.video
	AllowAudio          bool `json:"allow_audio"`           // allow m.audio
	AllowFiles          bool `json:"allow_files"`           // allow m.file
	AllowStickers       bool `json:"allow_stickers"`        // allow m.sticker event type
	DenyCustomReactions bool `json:"deny_custom_reactions"` // deny m.reaction events with mxc://-prefixed keys
}

func (n *NoMedia) Execute(ctx context.Context, pe *PolicyEvaluator, evt *event.Event, dry bool) (hit bool, err error) {
	if evt.Type != event.EventMessage && evt.Type != event.EventSticker && evt.Type != event.EventReaction {
		return false, nil // no-op
	}

	switch evt.Type {
	case event.EventMessage:
		content := evt.Content.AsMessage()
		if content.MsgType == event.MsgImage && !n.AllowImages {
			hit = true
		} else if content.MsgType == event.MsgVideo && !n.AllowVideos {
			hit = true
		} else if content.MsgType == event.MsgAudio && !n.AllowAudio {
			hit = true
		} else if content.MsgType == event.MsgFile && !n.AllowFiles {
			hit = true
		}
	case event.EventSticker:
		if !n.AllowStickers {
			hit = true
		}
	case event.EventReaction:
		content := evt.Content.AsReaction()
		if n.DenyCustomReactions && strings.HasPrefix(content.RelatesTo.Key, "mxc://") {
			hit = true
		}
	}
	if hit {
		displayType := evt.Type.Type
		if evt.Type == event.EventMessage {
			displayType = string(evt.Content.AsMessage().MsgType)
		}
		pe.Bot.Log.Trace().
			Str("protection", "no_media").
			Str("event_type", displayType).
			Bool("disallowed", hit).
			Stringer("sender", evt.Sender).
			Stringer("room_id", evt.RoomID).
			Stringer("event_id", evt.ID).
			Msg("no_media protection hit")
		// At least one of the patterns matched, redact and notify in the background
		go func() {
			var execErr error
			if !dry {
				_, execErr = pe.Bot.RedactEvent(ctx, evt.RoomID, evt.ID, mautrix.ReqRedact{Reason: "media was not allowed"})
			}
			if execErr == nil {
				pe.sendNotice(
					ctx,
					fmt.Sprintf(
						"Redacted [this event (`%s`)](%s) from [%s](%s) in [%s](%s) for containing disallowed media.",
						displayType,
						evt.RoomID.EventURI(evt.ID),
						evt.Sender,
						evt.Sender.URI(),
						evt.RoomID,
						evt.RoomID.URI(),
					),
				)
			} else {
				pe.Bot.Log.Err(execErr).Msg("failed to redact message for no_media")
			}
		}()
	}
	return hit, nil
}

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

func (i *InsecureRegistration) Kick(ctx context.Context, pe *PolicyEvaluator, evt *event.Event, target id.UserID, dry bool) {
	var err error
	if !dry {
		_, err = pe.Bot.KickUser(ctx, evt.RoomID, &mautrix.ReqKickUser{
			UserID: target,
			Reason: "insecure registration (no email or captcha) on your home server",
		})
	}
	if err == nil {
		pe.sendNotice(
			ctx,
			fmt.Sprintf(
				"Kicked [%s](%s) from [%s](%s) for joining from a homeserver (%s) that allows insecure registration.",
				target,
				target.URI(),
				evt.RoomID,
				evt.RoomID.URI(),
				target.Homeserver(),
			),
		)
	} else {
		pe.Bot.Log.Err(err).Msg("failed to kick user for insecure registration")
	}
}

func (i *InsecureRegistration) Execute(ctx context.Context, pe *PolicyEvaluator, evt *event.Event, dry bool) (hit bool, err error) {
	if i.expire == nil {
		i.expire = make(map[string]time.Time)
	}
	if i.cache == nil {
		i.cache = make(map[string]bool)
	}
	if evt.Type != event.StateMember {
		return false, nil // no-op
	}
	content := evt.Content.AsMember()
	if !content.Membership.IsInviteOrJoin() { // we only care about invites and joins
		return false, nil
	}

	// Check when the last lookup for this server name was
	target := id.UserID(*evt.StateKey)
	hs := target.Homeserver()
	i.lock.RLock()
	cached, ok := i.expire[hs]
	result, hasResult := i.cache[hs]
	i.lock.RUnlock()
	if ok && hasResult {
		// If the result is true (insecure) and less than 5 minutes old, it is fresh.
		// Secure results are cached for longer since they're less likely to be invalid.
		if (result && time.Since(cached) < 5*time.Minute) || (!result && time.Since(cached) < time.Hour) {
			if result {
				// Kick user and alert the management room
				go i.Kick(ctx, pe, evt, target, dry)
			}
			return result, nil // recently checked, skip
		}
		i.lock.Lock()
		delete(i.cache, hs)
		delete(i.expire, hs)
		i.lock.Unlock()
	}

	// Not recently checked, do a lookup
	i.lock.Lock()
	defer func() {
		// Cache the result
		if err == nil {
			i.cache[hs] = hit
			i.expire[hs] = time.Now()
		}
		i.lock.Unlock()
	}()
	pe.Bot.Log.Trace().Stringer("user_id", target).Msg("performing insecure registration check")
	baseUrl := resolveWellKnown(ctx, pe.Bot.Client.Client, hs)
	client, err := mautrix.NewClient(baseUrl, "", "")
	if err != nil {
		pe.Bot.Log.Err(err).Str("homeserver", hs).Msg("failed to create client for insecure registration check")
		return false, err
	}
	_, flows, err := client.Register(ctx, &mautrix.ReqRegister{})
	pe.Bot.Log.Trace().Stringer("user_id", target).Err(err).Msg("finished insecure registration check")
	if err != nil {
		if errors.Is(err, mautrix.MForbidden) || errors.Is(err, mautrix.MNotFound) {
			// Registration is disabled or handled externally
			pe.Bot.Log.Trace().Stringer("user_id", target).Msg("homeserver forbids registration.")
			return false, nil
		}
		pe.Bot.Log.Err(err).Str("homeserver", hs).Msg("failed to query registration flows for insecure registration check")
		return false, err
	}

	hit = flows.HasSingleStageFlow(mautrix.AuthTypeDummy)
	pe.Bot.Log.Trace().
		Str("homeserver", hs).
		Any("flows", flows.Flows).
		Bool("dangerous", hit).
		Msg("server has registration enabled")
	if hit {
		// Kick user and alert the management room
		go i.Kick(ctx, pe, evt, target, dry)
	}
	return hit, nil
}

// AntiFlood is a protection that redacts and bans users who send too many events in a given time period.
type AntiFlood struct {
	Limit          int              `json:"limit"` // how many events to allow before actioning
	Per            jsontime.Seconds `json:"per"`   // the timespan in which to count events
	MaxInfractions int              `json:"max_infractions,omitempty"`
	TrustServer    bool             `json:"trust_server,omitempty"` // if false, use local time, instead of evt origin
	counts         map[id.UserID]int
	expire         map[id.UserID]time.Time
	countLock      sync.Mutex
}

func (a *AntiFlood) Execute(ctx context.Context, pe *PolicyEvaluator, evt *event.Event, dry bool) (hit bool, err error) {
	if a.Limit <= 0 || evt.StateKey != nil {
		return false, nil // no-op
	}
	a.countLock.Lock()
	defer a.countLock.Unlock()
	if a.counts == nil {
		a.counts = make(map[id.UserID]int)
	}
	if a.expire == nil {
		a.expire = make(map[id.UserID]time.Time)
	}

	// Expire old counts
	now := time.Now()
	origin := time.UnixMilli(evt.Timestamp)
	if !a.TrustServer || origin.After(now.Add(1*time.Hour)) {
		if a.TrustServer {
			pe.Bot.Log.Warn().
				Str("protection", "anti_flood").
				Stringer("sender", evt.Sender).
				Stringer("room_id", evt.RoomID).
				Stringer("event_id", evt.ID).
				Time("event_origin", origin).
				Time("current_time", now).
				Msg("event origin time is more than 1 hour in the future; falling back to local time")
		}
		origin = now
	}
	for user, exp := range a.expire {
		if now.After(exp) {
			delete(a.counts, user)
			delete(a.expire, user)
		}
	}

	// Count event
	a.counts[evt.Sender]++
	expire, ok := a.expire[evt.Sender]
	if !ok || expire.Before(origin) {
		// If there isn't already an expiry, or the current expiry is before the event origin, set a new expiry
		expire = origin.Add(a.Per.Duration)
	}
	a.expire[evt.Sender] = expire
	pe.Bot.Log.Trace().
		Str("protection", "anti_flood").
		Stringer("sender", evt.Sender).
		Stringer("room_id", evt.RoomID).
		Stringer("event_id", evt.ID).
		Int("count", a.counts[evt.Sender]).
		Time("expires", expire).
		Int("infractions", a.counts[evt.Sender]-a.Limit).
		Msg("anti_flood count and expiry updated")

	if a.counts[evt.Sender] > a.Limit {
		hit = true
		infractions := a.counts[evt.Sender] - a.Limit
		// At least one of the patterns matched, redact and notify in the background
		go func() {
			var execErr error
			if !dry {
				_, execErr = pe.Bot.RedactEvent(ctx, evt.RoomID, evt.ID, mautrix.ReqRedact{Reason: "flooding"})
			}
			if execErr == nil {
				pe.sendNotice(
					ctx,
					fmt.Sprintf(
						"Redacted [this message](%s) from [%s](%s) in [%s](%s) for exceeding the flood "+
							"limit of %d events per %s with %d events (%d considered infractions).",
						evt.RoomID.EventURI(evt.ID),
						evt.Sender,
						evt.Sender.URI(),
						evt.RoomID,
						evt.RoomID.URI(),
						a.Limit,
						a.Per.String(),
						a.counts[evt.Sender],
						infractions,
					),
				)
			} else {
				pe.Bot.Log.Err(execErr).Msg("failed to redact message for anti_flood")
			}
		}()
		// If the infractions are over the limit, issue a ban
		if infractions >= a.MaxInfractions {
			go func() {
				var execErr error
				if !dry {
					_, execErr = pe.Bot.BanUser(
						ctx,
						evt.RoomID,
						&mautrix.ReqBanUser{
							Reason:              "too many recent events (flooding)",
							UserID:              evt.Sender,
							MSC4293RedactEvents: true,
						},
					)
				}
				if execErr == nil {
					pe.sendNotice(
						ctx,
						fmt.Sprintf(
							"Banned [%s](%s) from [%s](%s) for exceeding the flood infraction limit of %d infractions.",
							evt.Sender,
							evt.Sender.URI(),
							evt.RoomID,
							evt.RoomID.URI(),
							a.MaxInfractions,
						),
					)
				} else {
					pe.Bot.Log.Err(execErr).Msg("failed to ban user for anti_flood")
				}
			}()
		}
	}
	return hit, nil
}
