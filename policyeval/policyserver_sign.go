//go:build goexperiment.jsonv2

package policyeval

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"
)

func (ps *PolicyServer) HandleSign(
	ctx context.Context,
	roomVersion id.RoomVersion,
	evt *pdu.PDU,
	clientEvt *event.Event,
	evaluator *PolicyEvaluator,
) error {
	if ps.SigningKey == nil {
		return errors.New("policy server is not configured with a signing key")
	}
	log := zerolog.Ctx(ctx).With().
		Stringer("room_id", clientEvt.RoomID).
		Stringer("event_id", clientEvt.ID).
		Logger()

	log.Trace().Any("event", evt).Msg("Checking event received by policy server")
	rec, match := ps.getRecommendation(clientEvt, evaluator)
	if rec == PSRecommendationSpam {
		// Don't sign spam events
		log.Debug().Stringer("recommendations", match.Recommendations()).Msg("Event rejected for spam")
	} else {
		log.Trace().Msg("Event accepted")

		err := evt.Sign(roomVersion, ps.Federation.ServerName, "policy_server", ps.SigningKey.Priv)
		if err != nil {
			return fmt.Errorf("failed to add signature to PDU: %w", err)
		}
	}
	return nil
}
