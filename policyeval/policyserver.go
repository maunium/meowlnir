package policyeval

import (
	"context"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policylist"
)

type PolicyServer struct {
	Evaluator  *PolicyEvaluator
	Federation *federation.Client
	Auth       *federation.ServerAuth
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

type EventPDU struct {
	AuthEvents []id.EventID `json:"auth_events"`
	Content    *event.Event `json:"content"`
	Depth      int64        `json:"depth"`
	Hashes     struct {
		Sha256 string `json:"sha256"`
	} `json:"hashes"`
	OriginServerTS int64                        `json:"origin_server_ts"`
	PrevEvents     []id.EventID                 `json:"prev_events"`
	RoomID         id.RoomID                    `json:"room_id"`
	Sender         id.UserID                    `json:"sender"`
	Signatures     map[string]map[string]string `json:"signatures"`
	StateKey       *string                      `json:"state_key"`
	Type           event.Type                   `json:"type"`
	Unsigned       *event.Unsigned              `json:"unsigned"`
}

// MSC4284: https://github.com/matrix-org/matrix-spec-proposals/pull/4284

func (srv *PolicyServer) HandleCheck(ctx context.Context, pdu *event.Event) (*PolicyServerResponse, error) {
	var match policylist.Match
	logger := zerolog.Ctx(ctx).With().Stringer("room_id", pdu.RoomID).Stringer("event_id", pdu.ID).Logger()
	srv.Evaluator.protectedRoomsLock.RLock()
	_, protected := srv.Evaluator.protectedRooms[pdu.RoomID]
	srv.Evaluator.protectedRoomsLock.RUnlock()
	if !protected {
		logger.Trace().Msg("received check for unprotected room")
		return respPSOk, nil
	}
	logger.Trace().Interface("event", pdu).Msg("received check for protected room")

	watchedLists := srv.Evaluator.GetWatchedLists()
	match = srv.Evaluator.Store.MatchUser(watchedLists, pdu.Sender)
	if match != nil {
		logger.Warn().Stringer("recommendations", match.Recommendations()).Msg("event rejected for spam")
		return respPSSpam, nil
	}
	match = srv.Evaluator.Store.MatchServer(watchedLists, pdu.Sender.Homeserver())
	if match != nil {
		logger.Warn().Stringer("recommendations", match.Recommendations()).Msg("event rejected for spam")
		return respPSSpam, nil
	}
	// In theory, if a room is taken down and uses the policy server, we can prevent them sending further events
	match = srv.Evaluator.Store.MatchRoom(watchedLists, pdu.RoomID)
	if match != nil {
		logger.Warn().Stringer("recommendations", match.Recommendations()).Msg("event rejected for spam")
		return respPSSpam, nil
	}

	// Seems fine.
	logger.Trace().Msg("event accepted")
	return respPSOk, nil
}
