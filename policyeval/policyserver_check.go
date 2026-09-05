//go:build goexperiment.jsonv2 || go1.27

package policyeval

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/database"
	"go.mau.fi/meowlnir/policylist"
)

type BlockRecommendation struct {
	Error        error            `json:"error,omitempty"`
	Match        policylist.Match `json:"match,omitempty"`
	DisplayError string           `json:"display_error,omitempty"`
}

func (ps *PolicyServer) getRecommendation(
	ctx context.Context,
	pdu *pdu.PDU,
	roomVersion id.RoomVersion,
	evaluator *PolicyEvaluator,
	isOrigin, isLegacyCheck bool,
) (string, *BlockRecommendation, error) {
	if pdu.Sender == evaluator.Bot.UserID || evaluator.Admins.Has(pdu.Sender) {
		return "admin", nil, nil
	}
	err := evaluator.loadingComplete.Wait(ctx)
	if err != nil {
		return "", nil, err
	}
	watchedLists := evaluator.GetWatchedLists()
	match := evaluator.Store.MatchUser(watchedLists, pdu.Sender)
	if match != nil {
		recs := match.Recommendations()
		if recs.BanOrUnban != nil && recs.BanOrUnban.Recommendation != event.PolicyRecommendationUnban {
			return "", &BlockRecommendation{Match: match, DisplayError: "You are banned in this room"}, nil
		} else if recs.Mute != nil {
			return "", &BlockRecommendation{Match: match, DisplayError: fmt.Sprintf("You are muted in this room: %s", recs.Mute.Reason)}, nil
		}
	}
	match = evaluator.Store.MatchServer(watchedLists, pdu.Sender.Homeserver())
	if match != nil {
		recs := match.Recommendations()
		if recs.BanOrUnban != nil && recs.BanOrUnban.Recommendation != event.PolicyRecommendationUnban {
			return "", &BlockRecommendation{Match: match, DisplayError: "You are banned in this room"}, nil
		} else if recs.Mute != nil {
			return "", &BlockRecommendation{Match: match, DisplayError: fmt.Sprintf("You are muted in this room: %s", recs.Mute.Reason)}, nil
		}
	}
	if pdu.StateKey == nil && !pdu.VerifyContentHash() {
		return "", &BlockRecommendation{
			Error:        fmt.Errorf("mismatching content hash"),
			DisplayError: "Event is malformed",
		}, nil
	}
	if evaluator.protections != nil {
		clientEvt, err := pdu.ToClientEvent(roomVersion)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Stringer("room_id", pdu.RoomID).
				Msg("Failed to convert PDU to client event")
			return "", &BlockRecommendation{
				Error:        fmt.Errorf("failed to convert PDU to client event: %w", err),
				DisplayError: "Event is malformed",
			}, nil
		}
		if parseErr := clientEvt.Content.ParseRaw(clientEvt.Type); parseErr != nil {
			evaluator.Bot.Log.Err(parseErr).
				Stringer("room_id", pdu.RoomID).
				Stringer("event_id", clientEvt.ID).
				Msg("Failed to parse event content")
		}
		ctx = zerolog.Ctx(ctx).With().
			Stringer("room_id", pdu.RoomID).
			Stringer("event_id", clientEvt.ID).
			Logger().WithContext(ctx)
		if evaluator.ShouldExecuteProtections(ctx, clientEvt, true) {
			for name, prot := range evaluator.protections {
				zerolog.Ctx(ctx).Trace().Str("protection", name).Msg("Evaluating protection")
				rec, err := prot.Execute(ctx, ProtectionParams{
					Eval:     evaluator,
					Evt:      clientEvt,
					Policy:   true,
					IsOrigin: isOrigin,
					IsLegacy: isLegacyCheck,
				})
				if err != nil {
					zerolog.Ctx(ctx).Err(err).
						Stringer("room_id", pdu.RoomID).
						Stringer("event_id", clientEvt.ID).
						Str("protection", name).
						Msg("Failed to execute protection")
					continue
				}
				zerolog.Ctx(ctx).Trace().Bool("spam", rec).Str("protection", name).Msg("Evaluated protection")
				if rec {
					return "", &BlockRecommendation{
						Error:        fmt.Errorf("protections rejected event"),
						DisplayError: "This message has been rejected as probable spam",
					}, nil
				}
			}
		}
	}
	return "no reason to disallow", nil, nil
}

const PolicyServerKeyID id.KeyID = "ed25519:policy_server"
const fakeLegacyCheckServerName = "legacy.invalid"

func (ps *PolicyServer) HandleSign(
	ctx context.Context,
	roomVersion id.RoomVersion,
	evt *pdu.PDU,
	evaluator *PolicyEvaluator,
	originServer string,
) (string, error) {
	if ps.SigningKey == nil {
		return "", errors.New("policy server is not configured with a signing key")
	}
	evtID, err := evt.GetEventID(roomVersion)
	if err != nil {
		return "", fmt.Errorf("failed to calculate event ID: %w", err)
	}
	log := zerolog.Ctx(ctx).With().
		Stringer("room_id", evt.RoomID).
		Stringer("event_id", evtID).
		Logger()
	sig, err := ps.DB.PSSignature.Get(ctx, evtID)
	if err != nil {
		return "", fmt.Errorf("failed to fetch signature from database: %w", err)
	} else if sig != nil {
		log.Trace().
			Time("cached_at", sig.CreatedAt.Time).
			Str("signature", sig.Signature).
			Msg("Using cached result for sign request")
		evt.AddSignature(ps.Federation.ServerName, PolicyServerKeyID, sig.Signature)
		return "", nil
	}

	log.Trace().Any("event", evt).Msg("Checking event received by policy server")
	allowReason, blockRec, err := ps.getRecommendation(
		ctx,
		evt,
		roomVersion,
		evaluator,
		originServer == evt.Sender.Homeserver(),
		originServer == fakeLegacyCheckServerName,
	)
	if err != nil {
		return "", err
	}
	if blockRec != nil {
		// Don't sign spam events
		log.Debug().Any("recommendation", blockRec).Msg("Event rejected for spam")
		return blockRec.DisplayError, nil
	}
	log.Trace().Str("allow_reason", allowReason).Msg("Event accepted")

	err = evt.Sign(roomVersion, ps.Federation.ServerName, PolicyServerKeyID, ps.SigningKey.Priv)
	if err != nil {
		return "", fmt.Errorf("failed to add signature to PDU: %w", err)
	}
	newSig, ok := evt.Signatures[ps.Federation.ServerName][PolicyServerKeyID]
	if !ok {
		return "", errors.New("failed to retrieve signature after signing")
	}
	err = ps.DB.PSSignature.Put(ctx, &database.PSSignature{
		EventID:   evtID,
		Signature: newSig,
		CreatedAt: jsontime.UnixMilliNow(),
	})
	if err != nil {
		return "", fmt.Errorf("failed to store signature in database: %w", err)
	}
	return "", nil
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
	evaluator *PolicyEvaluator,
) (allow bool, err error) {
	log := zerolog.Ctx(ctx).With().
		Stringer("event_id", evtID).
		Stringer("room_id", pdu.RoomID).
		Logger()
	if pdu.VerifySignature(roomVersion, ps.Federation.ServerName, ps.getSigningKey) == nil {
		log.Trace().Msg("Valid signature from self, short-circuiting legacy check")
		return true, nil
	}
	_, err = ps.HandleSign(ctx, roomVersion, pdu, evaluator, fakeLegacyCheckServerName)
	if err != nil {
		return false, err
	}
	_, hasSig := pdu.Signatures[ps.Federation.ServerName][PolicyServerKeyID]
	if hasSig {
		return true, nil
	}
	return false, nil
}

func (ps *PolicyServer) HandleCachedLegacyCheck(ctx context.Context, evtID id.EventID) (bool, error) {
	log := zerolog.Ctx(ctx).With().
		Stringer("event_id", evtID).
		Logger()
	sig, err := ps.DB.PSSignature.Get(ctx, evtID)
	if err != nil {
		return false, fmt.Errorf("failed to fetch signature from database: %w", err)
	} else if sig != nil && sig.Signature != "" {
		log.Trace().Msg("Found signature in database, accepting legacy check")
		return true, nil
	} else if sig != nil {
		log.Trace().Msg("Found rejection in database, rejecting legacy check")
	} else {
		log.Trace().Msg("Event not found in database, rejecting legacy check")
	}
	return false, nil
}
