//go:build goexperiment.jsonv2

package policyeval

import (
	"context"
	"errors"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/federation/pdu"
)

func (ps *PolicyServer) HandleSign(
	ctx context.Context,
	evt *pdu.PDU,
	clientEvt *event.Event,
	evaluator *PolicyEvaluator,
	redact bool,
	caller string,
) (signatures map[string]map[string]string, err error) {
	if ps.SigningKey == nil {
		return nil, errors.New("policy server is not configured with a signing key")
	}
	log := zerolog.Ctx(ctx).With().
		Stringer("room_id", clientEvt.RoomID).
		Stringer("event_id", clientEvt.ID).
		Logger()
	finalRec := PSRecommendationOk
	defer func() {
		if caller != evt.Sender.Homeserver() && finalRec == PSRecommendationSpam && redact && ps.redactionCache.Add(clientEvt.ID) {
			go func() {
				if _, err = evaluator.Bot.RedactEvent(context.WithoutCancel(ctx), clientEvt.RoomID, clientEvt.ID); err != nil {
					log.Error().Err(err).Msg("Failed to redact event")
				}
			}()
		}
	}()

	log.Trace().Any("event", evt).Msg("Checking event received by policy server")
	rec, match := ps.getRecommendation(clientEvt, evaluator)
	finalRec = rec
	if rec == PSRecommendationSpam {
		// Don't sign spam events
		log.Debug().Stringer("recommendations", match.Recommendations()).Msg("Event rejected for spam")
	} else {
		log.Trace().Msg("Event accepted")

		var signature string
		signature, err = ps.SigningKey.SignJSON(evt)
		if err != nil {
			return
		}
		signatures = map[string]map[string]string{
			ps.Federation.ServerName: {
				"ed25519:policy_server": signature,
			},
		}
	}
	return signatures, nil
}
