package policyeval

import (
	"context"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policylist"
	"go.mau.fi/meowlnir/util"
)

type psCacheEntry struct {
	Recommendation PSRecommendation
	Timestamp      time.Time
	RoomID         id.RoomID
	PDU            *util.EventPDU
}

type PolicyServer struct {
	Federation *federation.Client
	ServerAuth *federation.ServerAuth
	EventCache map[id.EventID]*psCacheEntry
	cacheLock  *sync.RWMutex
}

func NewPolicyServer(serverName string) *PolicyServer {
	inMemCache := federation.NewInMemoryCache()
	fed := federation.NewClient(serverName, nil, inMemCache)
	return &PolicyServer{
		EventCache: make(map[id.EventID]*psCacheEntry),
		cacheLock:  &sync.RWMutex{},
		Federation: fed,
		ServerAuth: federation.NewServerAuth(fed, inMemCache, func(auth federation.XMatrixAuth) string {
			return auth.Destination
		}),
	}
}

func (ps *PolicyServer) getCachedRecommendation(evtID id.EventID) (*PolicyServerResponse, bool) {
	ps.cacheLock.RLock()
	resp, ok := ps.EventCache[evtID]
	ps.cacheLock.RUnlock()
	if ok {
		if time.Since(resp.Timestamp) < 5*time.Minute {
			return &PolicyServerResponse{Recommendation: resp.Recommendation}, true
		}
		ps.cacheLock.Lock()
		delete(ps.EventCache, evtID)
		ps.cacheLock.Unlock()
	}
	return nil, false
}

func (ps *PolicyServer) cacheRecommendation(evtID id.EventID, entry *psCacheEntry) {
	ps.cacheLock.Lock()
	defer ps.cacheLock.Unlock()
	ps.EventCache[evtID] = entry
	if len(ps.EventCache) > 1000 {
		// clear out old entries to save space
		for k := range ps.EventCache {
			if time.Since(ps.EventCache[k].Timestamp) > 5*time.Minute {
				delete(ps.EventCache, k)
			}
		}
	}
}

type PSRecommendation string

const (
	PSRecommendationOk   PSRecommendation = "ok"
	PSRecommendationSpam PSRecommendation = "spam"
)

type PolicyServerResponse struct {
	Recommendation PSRecommendation `json:"recommendation"`
	policy         *policylist.Match
}

var (
	respPSOk = &PolicyServerResponse{Recommendation: PSRecommendationOk}
)

// MSC4284: https://github.com/matrix-org/matrix-spec-proposals/pull/4284

func (ps *PolicyServer) getRecommendation(ctx context.Context, evtID id.EventID, pdu *util.EventPDU, evaluator *PolicyEvaluator) *PolicyServerResponse {
	logger := zerolog.Ctx(ctx).With().Stringer("room_id", pdu.RoomID).Stringer("event_id", evtID).Logger()
	watchedLists := evaluator.GetWatchedLists()
	match := evaluator.Store.MatchUser(watchedLists, pdu.Sender)
	res := &PolicyServerResponse{Recommendation: PSRecommendationSpam}
	if match != nil {
		res.policy = &match
		return res
	}
	match = evaluator.Store.MatchServer(watchedLists, pdu.Sender.Homeserver())
	if match != nil {
		res.policy = &match
		return res
	}
	// In theory, if a room is taken down and uses the policy server, we can prevent them sending further events
	match = evaluator.Store.MatchRoom(watchedLists, pdu.RoomID)
	if match != nil {
		res.policy = &match
		return res
	}
	// todo, in future, check against protections?

	// Event seems fine.
	logger.Trace().Msg("event accepted")
	return respPSOk
}

func (ps *PolicyServer) HandleCheck(ctx context.Context, evtID id.EventID, pdu *util.EventPDU, evaluator *PolicyEvaluator, redact bool) (res *PolicyServerResponse, err error) {
	if r, ok := ps.getCachedRecommendation(evtID); ok {
		return r, nil
	}
	logger := zerolog.Ctx(ctx).With().Stringer("room_id", pdu.RoomID).Stringer("event_id", evtID).Logger()
	logger.Trace().Interface("event", pdu).Msg("received check for protected room")
	res = ps.getRecommendation(ctx, evtID, pdu, evaluator)
	ps.cacheRecommendation(evtID, &psCacheEntry{
		Recommendation: res.Recommendation,
		Timestamp:      time.Now(),
		RoomID:         pdu.RoomID,
		PDU:            pdu,
	})
	if res.Recommendation == PSRecommendationSpam {
		logger.Warn().Stringer("recommendations", res.policy.Recommendations()).Msg("event rejected for spam")
		if redact {
			if _, err := evaluator.Bot.RedactEvent(ctx, pdu.RoomID, evtID); err != nil {
				logger.Error().Err(err).Msg("failed to redact event")
			}
		}
	} else {
		logger.Trace().Msg("event accepted")
	}
	return res, nil
}
