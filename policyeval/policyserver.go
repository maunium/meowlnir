package policyeval

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exsync"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/federation/pdu"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/policylist"
)

type psCacheEntry struct {
	Recommendation PSRecommendation
	Signatures     map[string]map[string]string
	LastAccessed   time.Time
	PDU            *event.Event
	Lock           sync.Mutex
}

type PolicyServer struct {
	Federation     *federation.Client
	ServerAuth     *federation.ServerAuth
	SigningKey     *federation.SigningKey
	eventCache     map[id.EventID]*psCacheEntry
	redactionCache *exsync.Set[id.EventID]
	cacheLock      sync.Mutex

	CacheMaxSize   int
	CacheMaxAge    time.Duration
	lastCacheClear time.Time
}

func NewPolicyServer(serverName string, signingKey *federation.SigningKey) *PolicyServer {
	inMemCache := federation.NewInMemoryCache()
	fed := federation.NewClient(serverName, nil, inMemCache)
	return &PolicyServer{
		eventCache:     make(map[id.EventID]*psCacheEntry),
		redactionCache: exsync.NewSet[id.EventID](),
		Federation:     fed,
		ServerAuth: federation.NewServerAuth(fed, inMemCache, func(auth federation.XMatrixAuth) string {
			return auth.Destination
		}),
		CacheMaxSize: 1000,
		CacheMaxAge:  5 * time.Minute,
		SigningKey:   signingKey,
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
		if pdu == nil {
			return nil
		}
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
	// TODO check protections
	return PSRecommendationOk, nil
}

func (ps *PolicyServer) HandleCachedCheck(evtID id.EventID) *PolicyServerResponse {
	r := ps.getCache(evtID, nil)
	if r == nil {
		return nil
	}
	r.Lock.Lock()
	defer r.Lock.Unlock()
	if r.Recommendation == "" {
		return nil
	}
	r.LastAccessed = time.Now()
	return &PolicyServerResponse{Recommendation: r.Recommendation}
}

func (ps *PolicyServer) HandleLegacyCheck(
	ctx context.Context,
	evtID id.EventID,
	pdu *event.Event,
	evaluator *PolicyEvaluator,
	redact bool,
	caller string,
) (res *PolicyServerResponse, err error) {
	log := zerolog.Ctx(ctx).With().
		Stringer("room_id", pdu.RoomID).
		Stringer("event_id", evtID).
		Logger()
	r := ps.getCache(evtID, pdu)
	finalRec := r.Recommendation
	r.Lock.Lock()
	defer func() {
		r.Lock.Unlock()
		// TODO if event is older than when the process was started, check if it was already redacted on the server
		if caller != pdu.Sender.Homeserver() && finalRec == PSRecommendationSpam && redact && ps.redactionCache.Add(pdu.ID) {
			go func() {
				if _, err = evaluator.Bot.RedactEvent(context.WithoutCancel(ctx), pdu.RoomID, evtID); err != nil {
					log.Error().Err(err).Msg("Failed to redact event")
				}
			}()
		}
	}()

	if r.Recommendation == "" {
		log.Trace().Any("event", pdu).Msg("Checking event received by policy server")
		rec, match := ps.getRecommendation(pdu, evaluator)
		finalRec = rec
		if rec == PSRecommendationSpam {
			log.Debug().Stringer("recommendations", match.Recommendations()).Msg("Event rejected for spam")
			r.Recommendation = rec
		} else {
			log.Trace().Msg("Event accepted")
		}
	}
	r.LastAccessed = time.Now()
	return &PolicyServerResponse{Recommendation: r.Recommendation}, nil
}

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
	r := ps.getCache(clientEvt.ID, clientEvt)
	finalRec := r.Recommendation
	r.Lock.Lock()
	defer func() {
		r.Lock.Unlock()
		if caller != evt.Sender.Homeserver() && finalRec == PSRecommendationSpam && redact && ps.redactionCache.Add(clientEvt.ID) {
			go func() {
				if _, err = evaluator.Bot.RedactEvent(context.WithoutCancel(ctx), clientEvt.RoomID, clientEvt.ID); err != nil {
					log.Error().Err(err).Msg("Failed to redact event")
				}
			}()
		}
	}()

	if r.Signatures == nil {
		log.Trace().Any("event", evt).Msg("Checking event received by policy server")
		rec, match := ps.getRecommendation(clientEvt, evaluator)
		finalRec = rec
		r.Recommendation = finalRec
		if rec == PSRecommendationSpam {
			// Don't sign spam events
			log.Debug().Stringer("recommendations", match.Recommendations()).Msg("Event rejected for spam")
			signatures = make(map[string]map[string]string) // empty but not nil map to prevent later rechecks
		} else {
			log.Trace().Msg("Event accepted")

			var signature string
			signature, err = ps.SigningKey.SignJSON(evt)
			if err != nil {
				return
			}
			signatures = map[string]map[string]string{
				clientEvt.Sender.Homeserver(): {
					string(ps.SigningKey.ID): signature,
				},
			}
		}
	}
	r.LastAccessed = time.Now()
	return signatures, nil
}
