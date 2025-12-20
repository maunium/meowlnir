package policyeval

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/meowlnir/bot"
	"go.mau.fi/meowlnir/config"
	"maunium.net/go/mautrix/commands"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/format"
	"maunium.net/go/mautrix/id"
)

func (pe *PolicyEvaluator) writableLists(ctx context.Context) map[id.RoomID]*config.WatchedPolicyList {
	lists := make(map[id.RoomID]*config.WatchedPolicyList)
	for roomID, list := range pe.watchedListsMap {
		if list.Shortcode == "" {
			continue
		}
		pl, err := pe.Bot.StateStore.GetPowerLevels(ctx, roomID)
		if err != nil || pl.GetEventLevel(event.StatePolicyUser) > pl.GetUserLevel(pe.Bot.UserID) {
			continue
		}
		lists[roomID] = list
	}
	return lists
}

func (pe *PolicyEvaluator) propagateBan(ctx context.Context, banEvent *event.Event) {
	content := banEvent.Content.AsMember()
	userID := id.UserID(banEvent.GetStateKey())
	actions := make(map[string]any, len(pe.watchedListsMap))
	for _, list := range pe.writableLists(ctx) {
		actions["/ban "+list.Shortcode] = fmt.Sprintf("!ban %s %s %s", list.Shortcode, userID, content.Reason)
		continue
	}
	if len(actions) == 0 {
		zerolog.Ctx(ctx).Debug().Msg("No writable policy lists to propagate ban to")
		return
	}

	msg := fmt.Sprintf(
		"%s was banned from %s by %s%s for %s. Copy to a policy list?",
		format.MarkdownMention(userID),
		format.MarkdownMentionRoomID("", banEvent.RoomID),
		format.MarkdownMention(banEvent.Sender),
		oldEventNotice(banEvent.Timestamp),
		format.SafeMarkdownCode(content.Reason),
	)
	evtID := pe.Bot.SendNoticeOpts(ctx, pe.ManagementRoom, msg, &bot.SendNoticeOpts{
		Extra: map[string]any{commands.ReactionCommandsKey: actions},
	})
	if evtID == "" {
		return
	}
	pe.sendReactions(ctx, evtID, slices.Collect(maps.Keys(actions))...)
}
func (pe *PolicyEvaluator) propagateUnban(ctx context.Context, unbanEvent *event.Event) {
	content := unbanEvent.Content.AsMember()
	userID := id.UserID(unbanEvent.GetStateKey())

	match := pe.Store.MatchUser(pe.GetWatchedLists(), userID)
	if len(match) == 0 {
		zerolog.Ctx(ctx).Debug().Msg("No matching policies to propagate unban to")
		return
	}

	actions := make(map[string]any, len(match))
	writeable := pe.writableLists(ctx)
	msg := fmt.Sprintf(
		"%s was unbanned from %s by %s%s for %s, but is still banned by %d policies. Do you want to remove any?\n",
		format.MarkdownMention(userID),
		format.MarkdownMentionRoomID("", unbanEvent.RoomID),
		format.MarkdownMention(unbanEvent.Sender),
		oldEventNotice(unbanEvent.Timestamp),
		format.SafeMarkdownCode(content.Reason),
		len(match),
	)
	n := 0
	for _, policy := range match {
		meta, ok := writeable[policy.RoomID]
		if !ok {
			continue
		}
		n++
		msg += fmt.Sprintf(
			"%d. [%s] %s set recommendation %s for %s at %s for %s",
			n,
			format.EscapeMarkdown(meta.Shortcode),
			format.MarkdownMention(policy.Sender),
			format.SafeMarkdownCode(policy.Recommendation),
			format.SafeMarkdownCode(policy.EntityOrHash()),
			format.EscapeMarkdown(time.UnixMilli(policy.Timestamp).String()),
			format.SafeMarkdownCode(policy.Reason),
		)
		actions[fmt.Sprintf("/remove %d", n)] = fmt.Sprintf("!remove-policy %s %s", meta.Shortcode, policy.EntityOrHash())
	}
	if len(actions) == 0 {
		return
	}

	evtID := pe.Bot.SendNoticeOpts(ctx, pe.ManagementRoom, msg, &bot.SendNoticeOpts{
		Extra: map[string]any{commands.ReactionCommandsKey: actions},
	})
	if evtID == "" {
		return
	}
	pe.sendReactions(ctx, evtID, slices.Collect(maps.Keys(actions))...)
}
