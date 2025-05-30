package policyeval

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policylist"
)

type psCacheEntry struct {
	Recommendation PSRecommendation
	LastAccessed   time.Time
	PDU            *event.Event
	Lock           sync.Mutex
}

type PolicyServer struct {
	Federation *federation.Client
	ServerAuth *federation.ServerAuth
	eventCache map[id.EventID]*psCacheEntry
	cacheLock  sync.Mutex

	CacheMaxSize   int
	CacheMaxAge    time.Duration
	lastCacheClear time.Time
}

func NewPolicyServer(serverName string) *PolicyServer {
	inMemCache := federation.NewInMemoryCache()
	fed := federation.NewClient(serverName, nil, inMemCache)
	return &PolicyServer{
		eventCache: make(map[id.EventID]*psCacheEntry),
		Federation: fed,
		ServerAuth: federation.NewServerAuth(fed, inMemCache, func(auth federation.XMatrixAuth) string {
			return auth.Destination
		}),
		CacheMaxSize: 1000,
		CacheMaxAge:  5 * time.Minute,
	}
}

func (ps *PolicyServer) UpdateRecommendation(userID id.UserID, roomIDs []id.RoomID, rec PSRecommendation) {
	ps.cacheLock.Lock()
	defer ps.cacheLock.Unlock()
	for _, cache := range ps.eventCache {
		if cache.PDU.Sender == userID && slices.Contains(roomIDs, cache.PDU.RoomID) {
			cache.Recommendation = rec
		}
	}
}

func (ps *PolicyServer) getCache(evtID id.EventID, pdu *event.Event) *psCacheEntry {
	ps.cacheLock.Lock()
	defer ps.cacheLock.Unlock()
	entry, ok := ps.eventCache[evtID]
	if !ok {
		ps.unlockedClearCacheIfNeeded()
		entry = &psCacheEntry{LastAccessed: time.Now(), PDU: pdu}
		ps.eventCache[evtID] = entry
	}
	return entry
}

func (ps *PolicyServer) unlockedClearCacheIfNeeded() {
	if len(ps.eventCache) > ps.CacheMaxSize && time.Since(ps.lastCacheClear) > 1*time.Minute {
		for evtID, entry := range ps.eventCache {
			if time.Since(entry.LastAccessed) > ps.CacheMaxAge {
				delete(ps.eventCache, evtID)
			}
		}
		ps.lastCacheClear = time.Now()
	}
}

type PSRecommendation string

const (
	PSRecommendationOk   PSRecommendation = "ok"
	PSRecommendationSpam PSRecommendation = "spam"
)

type PolicyServerResponse struct {
	Recommendation PSRecommendation `json:"recommendation"`
}

func (ps *PolicyServer) getRecommendation(pdu *event.Event, evaluator *PolicyEvaluator) (PSRecommendation, policylist.Match) {
	watchedLists := evaluator.GetWatchedLists()
	match := evaluator.Store.MatchUser(watchedLists, pdu.Sender)
	if match != nil {
		return PSRecommendationSpam, match
	}
	match = evaluator.Store.MatchServer(watchedLists, pdu.Sender.Homeserver())
	if match != nil {
		return PSRecommendationSpam, match
	}
	// TODO check protections
	return PSRecommendationOk, nil
}

func (ps *PolicyServer) HandleCheck(
	ctx context.Context,
	evtID id.EventID,
	pdu *event.Event,
	evaluator *PolicyEvaluator,
	redact bool,
) (res *PolicyServerResponse, err error) {
	r := ps.getCache(evtID, pdu)
	r.Lock.Lock()
	defer r.Lock.Unlock()
	if r.Recommendation == "" {
		log := zerolog.Ctx(ctx).With().Stringer("room_id", pdu.RoomID).Stringer("event_id", evtID).Logger()
		log.Trace().Any("event", pdu).Msg("Checking event received by policy server")
		rec, match := ps.getRecommendation(pdu, evaluator)
		r.Recommendation = rec
		if rec == PSRecommendationSpam {
			log.Debug().Stringer("recommendations", match.Recommendations()).Msg("Event rejected for spam")
			if redact {
				go func() {
					if _, err = evaluator.Bot.RedactEvent(context.WithoutCancel(ctx), pdu.RoomID, evtID); err != nil {
						log.Error().Err(err).Msg("Failed to redact event")
					}
				}()
			}
		} else {
			log.Trace().Msg("Event accepted")
		}
	}
	r.LastAccessed = time.Now()
	return &PolicyServerResponse{Recommendation: r.Recommendation}, nil
}
