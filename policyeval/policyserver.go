package policyeval

import (
	"context"

	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/util"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/federation"

	"go.mau.fi/meowlnir/policylist"
)

type PolicyServer struct {
	Federation *federation.Client
}

type PSRecommendation string

const (
	PSRecommendationOk   PSRecommendation = "ok"
	PSRecommendationSpam PSRecommendation = "spam"
)

type PolicyServerResponse struct {
	Recommendation PSRecommendation `json:"recommendation"`
}

var (
	respPSOk   = &PolicyServerResponse{Recommendation: PSRecommendationOk}
	respPSSpam = &PolicyServerResponse{Recommendation: PSRecommendationSpam}
)

// MSC4284: https://github.com/matrix-org/matrix-spec-proposals/pull/4284

func (srv *PolicyServer) HandleCheck(ctx context.Context, evtID id.EventID, pdu *util.EventPDU, evaluator *PolicyEvaluator) (*PolicyServerResponse, error) {
	var match policylist.Match
	logger := zerolog.Ctx(ctx).With().Stringer("room_id", pdu.RoomID).Stringer("event_id", evtID).Logger()
	logger.Trace().Interface("event", pdu).Msg("received check for protected room")

	watchedLists := evaluator.GetWatchedLists()
	match = evaluator.Store.MatchUser(watchedLists, pdu.Sender)
	if match != nil {
		logger.Warn().Stringer("recommendations", match.Recommendations()).Msg("event rejected for spam")
		return respPSSpam, nil
	}
	match = evaluator.Store.MatchServer(watchedLists, pdu.Sender.Homeserver())
	if match != nil {
		logger.Warn().Stringer("recommendations", match.Recommendations()).Msg("event rejected for spam")
		return respPSSpam, nil
	}
	// In theory, if a room is taken down and uses the policy server, we can prevent them sending further events
	match = evaluator.Store.MatchRoom(watchedLists, pdu.RoomID)
	if match != nil {
		logger.Warn().Stringer("recommendations", match.Recommendations()).Msg("event rejected for spam")
		return respPSSpam, nil
	}
	// todo, in future, check against protections?

	// Seems fine.
	logger.Trace().Msg("event accepted")
	return respPSOk, nil
}
