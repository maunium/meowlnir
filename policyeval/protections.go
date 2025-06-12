package policyeval

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"go.mau.fi/meowlnir/config"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
)

func MediaProtectionCallback(ctx context.Context, client *mautrix.Client, evt *event.Event, p *config.NoMediaProtection, dry bool) bool {
	// The room constraints and enabled-ness of the protection are already checked before this callback is called.
	protectionLog := zerolog.Ctx(ctx).With().
		Str("protection", "no_media").
		Stringer("room", evt.RoomID).
		Stringer("event", evt.ID).
		Stringer("sender", evt.Sender).
		Logger()
	powerLevels, err := client.StateStore.GetPowerLevels(ctx, evt.RoomID)
	if err != nil {
		protectionLog.Warn().Err(err).Msg("Failed to get power levels!")
	}
	if p.UserCanBypass(evt.Sender, powerLevels) {
		protectionLog.Trace().Msg("sender can bypass protection")
		return false
	}

	shouldRedact := false
	allowedTypes := []string{"m.text", "m.notice", "m.emote", "m.reaction"}
	if p.AllowedTypes != nil {
		allowedTypes = *p.AllowedTypes // text-only by default
	}

	if evt.Type == event.EventReaction && !p.AllowCustomReactions {
		if strings.HasPrefix(evt.Content.AsReaction().GetRelatesTo().Key, "mxc://") {
			shouldRedact = true
		}
	} else {
		var msgType string
		var msgContent *event.MessageEventContent

		if evt.Type == event.EventSticker {
			msgType = "m.sticker"
			// m.sticker is actually an event type, not message type. But, for all intents
			// and purposes, it's basically just m.image, and here we'll treat it as such
		} else {
			msgContent = evt.Content.AsMessage()
			msgType = string(msgContent.MsgType)
		}

		shouldRedact = !slices.Contains(allowedTypes, msgType)
		if msgContent != nil && !p.AllowInlineImages {
			// Lazy, but check for <img> tags in the body.
			if strings.Contains(msgContent.FormattedBody, "<img") {
				shouldRedact = true
			}
		}
	}

	if len(p.ForbidHomeservers) > 0 && slices.Contains(p.ForbidHomeservers, evt.Sender.Homeserver()) {
		shouldRedact = true
	}

	if shouldRedact && !dry {
		if _, err := client.RedactEvent(ctx, evt.RoomID, evt.ID); err != nil {
			protectionLog.Err(err).Msg("Failed to redact message")
		} else {
			protectionLog.Info().Msg("Redacted message")
		}
	}
	return shouldRedact
}

type eventWithMentions struct {
	Mentions *event.Mentions `json:"m.mentions"`
}

func MentionProtectionCallback(ctx context.Context, pe *PolicyEvaluator, evt *event.Event, p *config.MaxMentionsProtection, dry bool) bool {
	protectionLog := zerolog.Ctx(ctx).With().
		Str("protection", "max_mentions").
		Stringer("room", evt.RoomID).
		Stringer("event", evt.ID).
		Stringer("sender", evt.Sender).
		Logger()
	if p.MaxMentions <= 0 {
		protectionLog.Trace().Msg("protection disabled")
		return false
	}
	userMentions := 0
	var content eventWithMentions
	if err := json.Unmarshal(evt.Content.VeryRaw, &content); err != nil {
		protectionLog.Trace().Err(err).Msg("failed to parse event to check for mentions")
		return false
	}
	if content.Mentions != nil {
		userMentions = len(content.Mentions.UserIDs)
	}
	protectionLog.Trace().Int("mentions", userMentions).Msg("sender sent mentions")
	powerLevels, err := pe.Bot.Client.StateStore.GetPowerLevels(ctx, evt.RoomID)
	if err != nil {
		protectionLog.Warn().Err(err).Msg("Failed to get power levels!")
	}
	if p.UserCanBypass(evt.Sender, powerLevels) {
		protectionLog.Trace().Msg("sender can bypass protection")
		return false
	}

	spam := false
	if p.Period <= 0 {
		// Only check the event itself
		if userMentions >= p.MaxMentions {
			if !dry {
				if _, err := pe.Bot.Client.RedactEvent(ctx, evt.RoomID, evt.ID); err != nil {
					protectionLog.Err(err).Msg("Failed to redact message")
				} else {
					protectionLog.Info().Msg("Redacted message")
				}
			}
			spam = true
		}
	} else {
		u := p.IncrementUser(evt.Sender, userMentions)
		protectionLog.Trace().
			Int("mentions", u.Hits).
			Int("max", p.MaxMentions).
			Time("expires", u.Expires).
			Msg("sender has sent total mentions")
		if u.Hits >= p.MaxMentions && time.Now().Before(u.Expires) {
			infractionsToAdd := userMentions / p.MaxMentions
			u = p.IncrementInfractions(evt.Sender, infractionsToAdd)
			pe.sendNotice(ctx,
				"User [%s](%s) has sent too many mentions (%d in the past %s) in room [%s](%s) - redacting their [message](%s).",
				evt.Sender,
				evt.Sender.URI().MatrixToURL(),
				u.Hits,
				time.Since(u.Start),
				evt.RoomID,
				evt.RoomID.URI().MatrixToURL(),
				evt.RoomID.EventURI(evt.ID).MatrixToURL())
			if !dry {
				if _, err := pe.Bot.Client.RedactEvent(ctx, evt.RoomID, evt.ID); err != nil {
					protectionLog.Err(err).Msg("Failed to redact message")
				} else {
					protectionLog.Info().Msg("Redacted message")
				}
			}
			spam = true
		}
		if p.MaxInfractions != nil && u.Infractions >= *p.MaxInfractions {
			pe.sendNotice(ctx,
				"User [%s](%s) has reached the max infractions for mentions in room [%s](%s) - banning them.",
				evt.Sender,
				evt.Sender.URI().MatrixToURL(),
				evt.RoomID,
				evt.RoomID.URI().MatrixToURL())
			// Note: always ban even when `dry` is true. Dry is intended to prevent double redactions.
			_, banErr := pe.Bot.Client.BanUser(ctx, evt.RoomID, &mautrix.ReqBanUser{UserID: evt.Sender, Reason: "too many mentions"})
			if banErr != nil {
				protectionLog.Err(banErr).Msg("Failed to ban user")
				pe.sendNotice(ctx,
					"Failed to ban user [%s](%s) in room [%s](%s): %v",
					evt.Sender,
					evt.Sender.URI().MatrixToURL(),
					evt.RoomID,
					evt.RoomID.URI().MatrixToURL(),
					banErr)
			} else {
				protectionLog.Info().Msg("Banned user")
			}
			spam = true
		}
	}
	return spam
}

func ServerRequirementsProtectionCallback(ctx context.Context, pe *PolicyEvaluator, evt *event.Event, p *config.ServerRequirementsProtection) {
	// TODO: Don't check users/servers in hacky rules
	protectionLog := zerolog.Ctx(ctx).With().
		Str("protection", "server_requirements").
		Stringer("room", evt.RoomID).
		Stringer("event", evt.ID).
		Stringer("sender", evt.Sender).
		Logger()
	permitted, missing, err := p.CheckServer(ctx, evt.Sender.Homeserver())
	if err != nil {
		protectionLog.Warn().Err(err).Str("missing", *missing).Msg("Failed to check server")
		pe.sendNotice(
			ctx,
			"Failed to check server `%s` for user [%s](%s) in room [%s](%s): %v",
			evt.Sender.Homeserver())
		return
	}
	if !*permitted {
		protectionLog.Warn().Msg("Server has not passed requirements!")
		pe.sendNotice(
			ctx,
			"Server `%s` does not meet the registration requirements of room [%s](%s), missing: %s. kicking [%s](%s).",
			evt.Sender.Homeserver(),
			evt.RoomID,
			evt.RoomID.URI().MatrixToURL(),
			*missing,
			evt.Sender,
			evt.Sender.URI().MatrixToURL())
		if _, err := pe.Bot.Client.KickUser(ctx, evt.RoomID, &mautrix.ReqKickUser{
			UserID: evt.Sender,
			Reason: "Server does not meet registration requirements",
		}); err != nil {
			protectionLog.Err(err).Msg("Failed to kick user")
			pe.sendNotice(
				ctx,
				"Failed to kick user [%s](%s) in room [%s](%s): %v",
				evt.Sender,
				evt.Sender.URI().MatrixToURL(),
				evt.RoomID,
				evt.RoomID.URI().MatrixToURL(),
				err)
		} else {
			protectionLog.Info().Msg("Kicked user")
		}
	} else {
		protectionLog.Debug().Msg("Server has passed requirements")
	}
}

func (pe *PolicyEvaluator) handleProtections(
	evt *event.Event,
) (output, errors []string) {
	if evt.Content.Parsed == nil {
		if err := evt.Content.ParseRaw(config.StateProtections); err != nil {
			errors = append(errors, "failed to parse protections")
			return
		}
	}
	content, ok := evt.Content.Parsed.(*config.StateProtectionsEventContent)
	if !ok {
		errors = append(errors, "failed to parse protections")
		return
	}
	pe.protections = content
	// TODO: Diff changes(?)
	output = append(output, "Protections updated")
	return
}
