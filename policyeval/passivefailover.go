package policyeval

import (
	"context"
	"time"

	"go.mau.fi/meowlnir/config"
	"maunium.net/go/mautrix/event"
)

func (pe *PolicyEvaluator) handlePassiveFailover(ctx context.Context, evt *event.Event) (output, errors []string) {
	content, ok := evt.Content.Parsed.(*config.PassiveFailoverContent)
	if !ok {
		return nil, []string{"* Failed to parse protected rooms event"}
	}
	if pe.passiveFailoverTicker != nil {
		pe.passiveFailoverTicker.Stop()
		pe.passiveFailoverTicker = nil
	}
	if content.RoomID == "" {
		pe.claimCommunication(content.RoomID, pe, false)
		return []string{"* Disabled passive fallback mode"}, nil
	} else if content.RoomID != pe.passiveFailoverRoom {
		pe.claimCommunication(content.RoomID, pe, true)
		output = append(output, "* Enabled passive fallback mode in "+content.RoomID.String())
		pe.passiveFailoverRoom = content.RoomID
	}
	if content.Primary == "" {
		pe.passiveFailoverPrimary = ""
	} else if content.Primary != pe.passiveFailoverPrimary {
		output = append(output, "* Set primary instance user to "+content.Primary.String())
		pe.passiveFailoverPrimary = content.Primary
	}
	if content.Interval == 0 {
		content.Interval = 5 * time.Minute
		pe.passiveFailoverInterval = content.Interval
	} else if content.Interval != pe.passiveFailoverInterval {
		output = append(output, "* Set passive failover check interval to "+content.Interval.String())
		pe.passiveFailoverInterval = content.Interval
	}
	if content.Timeout == 0 {
		content.Timeout = 10 * time.Second
		pe.passiveFailoverTimeout = content.Timeout
	} else if content.Timeout != pe.passiveFailoverTimeout {
		output = append(output, "* Set passive failover timeout to "+content.Timeout.String())
		pe.passiveFailoverTimeout = content.Timeout
	}
	pe.passiveFailoverEvent = content
	pe.passiveFailoverTicker = time.NewTicker(pe.passiveFailoverInterval)
	go func() {
		pe.sendPassiveFailoverPing(ctx) // get initial ping out
		pe.passiveFailoverTask(ctx, pe.passiveFailoverTicker.C)
	}()
	return output, errors
}

func (pe *PolicyEvaluator) HandlePassiveFailoverPing(ctx context.Context, evt *event.Event) {
	if evt.Sender == pe.Bot.UserID {
		return
	}
	if evt.RoomID != pe.passiveFailoverRoom {
		pe.Bot.Log.Trace().
			Stringer("room", evt.RoomID).
			Msg("Ignoring ping request in unknown passive failover room")
		return
	}
	// Send a pong back
	content, ok := evt.Content.Parsed.(*config.PassiveFailoverPing)
	if !ok {
		pe.Bot.Log.Error().Msg("Failed to parse passive failover ping event")
		return
	}
	if content.Target != pe.Bot.UserID {
		pe.Bot.Log.Trace().
			Stringer("target", content.Target).
			Msg("Ignoring ping request not targeted at this instance")
		return
	}
	_, err := pe.Bot.SendMessageEvent(
		ctx,
		evt.RoomID,
		config.EventPassiveFailoverPong,
		&config.PassiveFailoverPong{
			RelatesTo: event.RelatesTo{InReplyTo: &event.InReplyTo{EventID: evt.ID}},
		},
	)
	if err != nil {
		pe.Bot.Log.Err(err).Msg("Failed to send passive failover pong")
		return
	}
}

func (pe *PolicyEvaluator) HandlePassiveFailoverPong(ctx context.Context, evt *event.Event) {
	if evt.Sender == pe.Bot.UserID {
		return
	}
	if evt.RoomID != pe.passiveFailoverRoom {
		pe.Bot.Log.Trace().
			Stringer("room", evt.RoomID).
			Msg("Ignoring pong in unknown passive failover room")
		return
	}
	if evt.Sender != pe.passiveFailoverPrimary {
		pe.Bot.Log.Trace().
			Stringer("sender", evt.Sender).
			Msg("Ignoring pong not from primary instance")
		return
	}
	content, ok := evt.Content.Parsed.(*config.PassiveFailoverPong)
	if !ok {
		pe.Bot.Log.Error().Msg("Failed to parse passive failover pong event")
		return
	}
	if content.RelatesTo.InReplyTo == nil || content.RelatesTo.InReplyTo.EventID != pe.passiveFailoverLastEvent {
		pe.Bot.Log.Trace().
			Stringer("event_id", evt.ID).
			Msg("Ignoring pong not related to last ping")
		return
	}
	pe.passiveFailoverLastPing = time.Now()
	pe.SetStandbyMode(ctx, time.Since(pe.passiveFailoverLastPong) <= pe.passiveFailoverTimeout)
}

func (pe *PolicyEvaluator) SetStandbyMode(ctx context.Context, standby bool) {
	previouslyInStandby := pe.standby
	pe.standby = standby
	pe.Bot.Log.Trace().
		Bool("previously_in_standby", previouslyInStandby).
		Bool("currently_in_standby", standby).
		Msg("Set standby mode")
	if previouslyInStandby && !standby {
		pe.sendNotice(ctx, "Exiting standby mode, primary did not pong in time.")
		go pe.EvaluateAll(ctx)
	} else if !previouslyInStandby && standby {
		pe.sendNotice(ctx, "Entering standby mode, primary is responding again.")
	}
}

func (pe *PolicyEvaluator) sendPassiveFailoverPing(ctx context.Context) {
	if pe.passiveFailoverRoom != "" && pe.passiveFailoverPrimary != "" {
		pe.Bot.Log.Debug().
			Stringer("room_id", pe.passiveFailoverPrimary).
			Stringer("primary", pe.passiveFailoverPrimary).
			Msg("Sending passive failover ping")
		resp, err := pe.Bot.SendMessageEvent(
			ctx,
			pe.passiveFailoverRoom,
			config.EventPassiveFailoverPing,
			&config.PassiveFailoverPing{
				Target: pe.passiveFailoverPrimary,
			},
		)
		if err != nil {
			pe.Bot.Log.Err(err).Msg("Failed to send passive failover ping")
			return
		}
		pe.passiveFailoverLastEvent = resp.EventID
		pe.passiveFailoverLastPing = time.Now()
		pe.Bot.Log.Trace().Msg("waiting for pong...")
		time.AfterFunc(pe.passiveFailoverTimeout, func() {
			// If the time since the last pong is greater than the timeout, we didn't get a pong in time
			if time.Since(pe.passiveFailoverLastPong) <= pe.passiveFailoverTimeout {
				pe.Bot.Log.Trace().Msg("pong received in time, no action needed")
				return
			}
			pe.Bot.Log.Warn().
				Stringer("room_id", pe.passiveFailoverRoom).
				Stringer("primary", pe.passiveFailoverPrimary).
				Time("last_ping", pe.passiveFailoverLastPing).
				Time("last_pong", pe.passiveFailoverLastPong).
				Dur("timeout", pe.passiveFailoverTimeout).
				Msg("Pong not received in time from primary")
			pe.SetStandbyMode(ctx, false)
		})
	}
}

func (pe *PolicyEvaluator) passiveFailoverTask(ctx context.Context, c <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c:
			pe.sendPassiveFailoverPing(ctx)
		}
	}
}
