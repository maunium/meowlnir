package policyeval

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/event"
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
				ctx, `[%s](%s) reported [an event](%s) for %s, but the event could not be fetched: %v`,
				sender, sender.URI().MatrixToURL(), roomID.EventURI(eventID).MatrixToURL(), reason, err,
			)
			return fmt.Errorf("failed to fetch event: %w", err)
		}
		targetUserID = evt.Sender
	}
	if !pe.Admins.Has(sender) || !strings.HasPrefix(reason, "/") || targetUserID == "" {
		if eventID != "" {
			pe.sendNotice(
				ctx, `[%s](%s) reported [an event](%s) from [%s](%s) for %s`,
				sender, sender.URI().MatrixToURL(), roomID.EventURI(eventID).MatrixToURL(),
				evt.Sender, evt.Sender.URI().MatrixToURL(),
				reason,
			)
		} else if roomID != "" {
			pe.sendNotice(
				ctx, `[%s](%s) reported [a room](%s) for %s`,
				sender, sender.URI().MatrixToURL(), roomID.URI().MatrixToURL(),
				reason,
			)
		} else if targetUserID != "" {
			pe.sendNotice(
				ctx, `[%s](%s) reported [%s](%s) for %s`,
				sender, sender.URI().MatrixToURL(), targetUserID.URI().MatrixToURL(),
				reason,
			)
		}
		return nil
	}
	fields := strings.Fields(reason)
	cmd := strings.TrimPrefix(fields[0], "/")
	args := fields[1:]
	switch strings.ToLower(cmd) {
	case "ban":
		if len(args) < 2 {
			return mautrix.MInvalidParam.WithMessage("Not enough arguments for ban")
		}
		list := pe.FindListByShortcode(args[0])
		if list == nil {
			pe.sendNotice(ctx, `Failed to handle [%s](%s)'s report of [%s](%s): list %q not found`,
				sender, sender.URI().MatrixToURL(), targetUserID, targetUserID.URI().MatrixToURL(), args[0])
			return mautrix.MNotFound.WithMessage(fmt.Sprintf("List with shortcode %q not found", args[0]))
		}
		match := pe.Store.MatchUser([]id.RoomID{list.RoomID}, targetUserID)
		if rec := match.Recommendations().BanOrUnban; rec != nil {
			if rec.Recommendation == event.PolicyRecommendationUnban {
				return mautrix.RespError{
					ErrCode:    "FI.MAU.MEOWLNIR.UNBAN_RECOMMENDED",
					Err:        fmt.Sprintf("%s has an unban recommendation: %s", targetUserID, rec.Reason),
					StatusCode: http.StatusConflict,
				}
			} else {
				return mautrix.RespError{
					ErrCode:    "FI.MAU.MEOWLNIR.ALREADY_BANNED",
					Err:        fmt.Sprintf("%s is already banned for: %s", targetUserID, rec.Reason),
					StatusCode: http.StatusConflict,
				}
			}
		}
		policy := &event.ModPolicyContent{
			Entity:         string(targetUserID),
			Reason:         strings.Join(args[1:], " "),
			Recommendation: event.PolicyRecommendationBan,
		}
		resp, err := pe.SendPolicy(ctx, list.RoomID, policylist.EntityTypeUser, "", string(targetUserID), policy)
		if err != nil {
			pe.sendNotice(ctx, `Failed to handle [%s](%s)'s report of [%s](%s) for %s ([%s](%s)): %v`,
				sender, sender.URI().MatrixToURL(), targetUserID, targetUserID.URI().MatrixToURL(),
				list.Name, list.RoomID, list.RoomID.URI().MatrixToURL(), err)
			return fmt.Errorf("failed to send policy: %w", err)
		}
		zerolog.Ctx(ctx).Info().
			Stringer("policy_list", list.RoomID).
			Any("policy", policy).
			Stringer("policy_event_id", resp.EventID).
			Msg("Sent ban policy from report")
		pe.sendNotice(ctx, `Processed [%s](%s)'s report of [%s](%s) and sent a ban policy to %s ([%s](%s)) for %s`,
			sender, sender.URI().MatrixToURL(), targetUserID, targetUserID.URI().MatrixToURL(),
			list.Name, list.RoomID, list.RoomID.URI().MatrixToURL(), policy.Reason)
	}
	return nil
}
