package policyeval

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policylist"
)

func (pe *PolicyEvaluator) HandleReport(ctx context.Context, senderClient *mautrix.Client, targetUserID id.UserID, roomID id.RoomID, eventID id.EventID, reason string) error {
	sender := senderClient.UserID
	var evt *event.Event
	var err error
	if eventID != "" {
		evt, err = senderClient.GetEvent(ctx, roomID, eventID)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).Msg("Failed to get report target event with user's token")
			pe.sendNotice(
				ctx, `%s reported [an event](%s) for %s, but the event could not be fetched: %v`,
				format.MarkdownMention(sender), roomID.EventURI(eventID).MatrixToURL(), reason, err,
			)
			return fmt.Errorf("failed to fetch event: %w", err)
		}
		targetUserID = evt.Sender
	}
	if !pe.Admins.Has(sender) || !strings.HasPrefix(reason, "/") || targetUserID == "" {
		if eventID != "" {
			pe.sendNotice(
				ctx, `%s reported [an event](%s) from ||%s|| for %s`,
				format.MarkdownMention(sender), roomID.EventURI(eventID).MatrixToURL(),
				format.MarkdownMention(evt.Sender), reason,
			)
		} else if roomID != "" {
			pe.sendNotice(
				ctx, `%s reported ||[a room](%s)|| for %s`,
				format.MarkdownMention(sender), roomID.URI().MatrixToURL(), reason,
			)
		} else if targetUserID != "" {
			pe.sendNotice(
				ctx, `%s reported ||%s|| for %s`,
				format.MarkdownMention(sender), format.MarkdownMention(targetUserID), reason,
			)
		}
		return nil
	}
	fields := strings.Fields(reason)
	cmd := strings.ToLower(strings.TrimPrefix(fields[0], "/"))
	args := fields[1:]
	switch cmd {
	case "ban", "banserver":
		if len(args) < 2 {
			return mautrix.MInvalidParam.WithMessage("Not enough arguments for ban")
		}
		list := pe.FindListByShortcode(args[0])
		if list == nil {
			pe.sendNotice(ctx, `Failed to handle %s's report of %s: list %q not found`,
				format.MarkdownMention(sender), format.MarkdownMention(targetUserID), args[0])
			return mautrix.MNotFound.WithMessage(fmt.Sprintf("List with shortcode %q not found", args[0]))
		}
		var (
			target, targetPretty string
			match                policylist.Match
			policyType           policylist.EntityType
		)
		if cmd == "ban" {
			target = targetUserID.String()
			targetPretty = format.MarkdownMention(targetUserID)
			match = pe.Store.MatchUser([]id.RoomID{list.RoomID}, targetUserID)
			policyType = policylist.EntityTypeUser
		} else {
			target = targetUserID.Homeserver()
			targetPretty = target
			match = pe.Store.MatchServer([]id.RoomID{list.RoomID}, target)
			policyType = policylist.EntityTypeServer
		}
		if rec := match.Recommendations().BanOrUnban; rec != nil {
			if rec.Recommendation == event.PolicyRecommendationUnban {
				return mautrix.RespError{
					ErrCode:    "FI.MAU.MEOWLNIR.UNBAN_RECOMMENDED",
					Err:        fmt.Sprintf("%s has an unban recommendation: %s", target, rec.Reason),
					StatusCode: http.StatusConflict,
				}
			} else {
				return mautrix.RespError{
					ErrCode:    "FI.MAU.MEOWLNIR.ALREADY_BANNED",
					Err:        fmt.Sprintf("%s is already banned for: %s", target, rec.Reason),
					StatusCode: http.StatusConflict,
				}
			}
		}
		policy := &event.ModPolicyContent{
			Entity:         target,
			Reason:         strings.Join(args[1:], " "),
			Recommendation: event.PolicyRecommendationBan,
		}
		resp, err := pe.SendPolicy(ctx, list.RoomID, policyType, "", target, policy)
		if err != nil {
			pe.sendNotice(ctx, `Failed to handle %s's report of ||%s|| for %s: %v`,
				format.MarkdownMention(sender), targetPretty,
				format.MarkdownMentionRoomID(list.Name, list.RoomID), err)
			return fmt.Errorf("failed to send policy: %w", err)
		}
		zerolog.Ctx(ctx).Info().
			Stringer("policy_list", list.RoomID).
			Any("policy", policy).
			Stringer("policy_event_id", resp.EventID).
			Msg("Sent ban policy from report")
		pe.sendNotice(ctx, `Processed %s's report of ||%s|| and sent a ban policy to %s for %s`,
			format.MarkdownMention(sender), targetPretty,
			format.MarkdownMentionRoomID(list.Name, list.RoomID), policy.Reason)
	}
	return nil
}
