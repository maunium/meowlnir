//go:build goexperiment.jsonv2

package policyeval

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policylist"
)

func (ps *PolicyServer) getRecommendation(ctx context.Context, pdu *pdu.PDU, roomVersion id.RoomVersion, evaluator *PolicyEvaluator) (PSRecommendation, policylist.Match) {
	watchedLists := evaluator.GetWatchedLists()
	match := evaluator.Store.MatchUser(watchedLists, pdu.Sender)
	if match != nil {
		rec := match.Recommendations().BanOrUnban
		if rec != nil && rec.Recommendation != event.PolicyRecommendationUnban {
			return PSRecommendationSpam, match
		}
	}
	match = evaluator.Store.MatchServer(watchedLists, pdu.Sender.Homeserver())
	if match != nil {
		rec := match.Recommendations().BanOrUnban
		if rec != nil && rec.Recommendation != event.PolicyRecommendationUnban {
			return PSRecommendationSpam, match
		}
	}
	if evaluator.protections != nil {
		evtID, err := pdu.GetEventID(roomVersion)
		if err != nil {
			evaluator.Bot.Log.Err(err).
				Stringer("room_id", pdu.RoomID).
				Msg("Failed to calculate event ID")
			return PSRecommendationOk, nil
		}
		pl, err := evaluator.getPowerLevels(ctx, pdu.RoomID)
		if err != nil || pl == nil {
			evaluator.Bot.Log.Err(err).
				Stringer("room_id", pdu.RoomID).
				Stringer("event_id", evtID).
				Msg("Failed to fetch power levels")
		}
		if pl != nil {
			// Don't act if the user is a room mod
			if pl.GetUserLevel(pdu.Sender) >= pl.Kick() {
				return PSRecommendationOk, nil
			}
		}
		clientEvt, err := pdu.ToClientEvent(roomVersion)
		if err != nil {
			evaluator.Bot.Log.Err(err).
				Stringer("room_id", pdu.RoomID).
				Stringer("event_id", evtID).
				Msg("Failed to convert PDU to client event")
			return PSRecommendationOk, nil
		}
		if parseErr := clientEvt.Content.ParseRaw(clientEvt.Type); parseErr != nil {
			evaluator.Bot.Log.Err(parseErr).
				Stringer("room_id", pdu.RoomID).
				Stringer("event_id", evtID).
				Msg("Failed to parse event content")
		}
		ctx = zerolog.Ctx(ctx).With().
			Stringer("room_id", pdu.RoomID).
			Stringer("event_id", clientEvt.ID).
			Logger().WithContext(ctx)
		for name, prot := range evaluator.protections {
			zerolog.Ctx(ctx).Trace().Msgf("Evaluating protection '%s'", name)
			rec, err := prot.Execute(ctx, evaluator, clientEvt, true)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).
					Stringer("room_id", pdu.RoomID).
					Stringer("event_id", evtID).
					Str("protection", name).
					Msg("Failed to execute protection")
				continue
			}
			zerolog.Ctx(ctx).Trace().Bool("spam", rec).Msgf("Evaluated protection '%s'", name)
			if rec {
				return PSRecommendationSpam, nil
			}
		}
	}
	return PSRecommendationOk, nil
}

const PolicyServerKeyID id.KeyID = "ed25519:policy_server"

func (ps *PolicyServer) HandleSign(
	ctx context.Context,
	roomVersion id.RoomVersion,
	evt *pdu.PDU,
	evaluator *PolicyEvaluator,
) error {
	if ps.SigningKey == nil {
		return errors.New("policy server is not configured with a signing key")
	}
	evtID, err := evt.GetEventID(roomVersion)
	if err != nil {
		return fmt.Errorf("failed to calculate event ID: %w", err)
	}
	log := zerolog.Ctx(ctx).With().
		Stringer("room_id", evt.RoomID).
		Stringer("event_id", evtID).
		Logger()

	log.Trace().Any("event", evt).Msg("Checking event received by policy server")
	rec, match := ps.getRecommendation(ctx, evt, roomVersion, evaluator)
	if rec == PSRecommendationSpam {
		// Don't sign spam events
		log.Debug().Stringer("recommendations", match.Recommendations()).Msg("Event rejected for spam")
	} else {
		log.Trace().Msg("Event accepted")

		err := evt.Sign(roomVersion, ps.Federation.ServerName, PolicyServerKeyID, ps.SigningKey.Priv)
		if err != nil {
			return fmt.Errorf("failed to add signature to PDU: %w", err)
		}
	}
	return nil
}

func (ps *PolicyServer) getSigningKey(serverName string, keyID id.KeyID, minValidUntil time.Time) (id.SigningKey, time.Time, error) {
	if serverName == ps.Federation.ServerName && keyID == PolicyServerKeyID {
		return ps.SigningKey.Pub, time.Now().Add(24 * time.Hour), nil
	}
	return "", time.Time{}, nil
}

func (ps *PolicyServer) HandleLegacyCheck(
	ctx context.Context,
	roomVersion id.RoomVersion,
	evtID id.EventID,
	pdu *pdu.PDU,
	clientEvt *event.Event,
	evaluator *PolicyEvaluator,
	redact bool,
	caller string,
) (res *LegacyPolicyServerResponse, err error) {
	log := zerolog.Ctx(ctx).With().
		Stringer("room_id", pdu.RoomID).
		Stringer("event_id", evtID).
		Logger()
	if pdu.VerifySignature(roomVersion, ps.Federation.ServerName, ps.getSigningKey) == nil {
		log.Trace().Msg("Valid signature from self, short-circuiting legacy check")
		res = &LegacyPolicyServerResponse{Recommendation: PSRecommendationOk}
		return res, nil
	}
	r := ps.getCache(evtID, clientEvt)
	finalRec := r.Recommendation
	r.Lock.Lock()
	defer func() {
		r.Lock.Unlock()
		// TODO if event is older than when the process was started, check if it was already redacted on the server
		if caller != pdu.Sender.Homeserver() && finalRec == PSRecommendationSpam && redact && ps.redactionCache.Add(evtID) {
			go func() {
				if _, err = evaluator.Bot.RedactEvent(context.WithoutCancel(ctx), pdu.RoomID, evtID); err != nil {
					log.Error().Err(err).Msg("Failed to redact event")
				}
			}()
		}
	}()

	if r.Recommendation == "" {
		log.Trace().Any("event", pdu).Msg("Checking event received by policy server")
		rec, match := ps.getRecommendation(ctx, pdu, roomVersion, evaluator)
		finalRec = rec
		if rec == PSRecommendationSpam {
			log.Debug().Stringer("recommendations", match.Recommendations()).Msg("Event rejected for spam")
			r.Recommendation = rec
		} else {
			log.Trace().Msg("Event accepted")
		}
	}
	r.LastAccessed = time.Now()
	return &LegacyPolicyServerResponse{Recommendation: r.Recommendation}, nil
}
