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

func (ps *PolicyServer) getRecommendation(ctx context.Context, pdu *event.Event, evaluator *PolicyEvaluator) (PSRecommendation, policylist.Match) {
	logger := zerolog.Ctx(ctx).With().Stringer("sender", pdu.Sender).Logger()
	watchedLists := evaluator.GetWatchedLists()
	match := evaluator.Store.MatchUser(watchedLists, pdu.Sender)
	if match != nil {
		rec := match.Recommendations().BanOrUnban
		if rec != nil && rec.Recommendation != event.PolicyRecommendationUnban {
			logger.Info().Stringer("recommendation", match.Recommendations()).Msg("Event rejected for user ban")
			return PSRecommendationSpam, match
		}
	}
	match = evaluator.Store.MatchServer(watchedLists, pdu.Sender.Homeserver())
	if match != nil {
		rec := match.Recommendations().BanOrUnban
		if rec != nil && rec.Recommendation != event.PolicyRecommendationUnban {
			logger.Info().Stringer("recommendation", match.Recommendations()).Msg("Event rejected for server ban")
			return PSRecommendationSpam, match
		}
	}
	// TODO check protections
	// TODO: unify protections calling, because this is duplicated and inefficient
	if evaluator.protections != nil {
		protections := evaluator.protections.GetProtectionsForRoom(pdu.RoomID)
		if protections != nil {
			logger.Trace().Interface("protections", protections).Msg("found protections for room")
			if pdu.Type == event.EventMessage {
				if protections.MaxMentions != nil && protections.MaxMentions.Enabled {
					logger.Trace().Msg("calling mention protection callback")
					spam := MentionProtectionCallback(ctx, evaluator, pdu, protections.MaxMentions, true)
					if spam {
						logger.Info().Msg("Event rejected for max mentions")
						return PSRecommendationSpam, nil
					}
					logger.Debug().Msg("event passed max mentions check")
				}
				if protections.NoMedia.Enabled {
					logger.Trace().Msg("calling media protection callback")
					spam := MediaProtectionCallback(ctx, evaluator.Bot.Client, pdu, &protections.NoMedia, true)
					if spam {
						logger.Info().Msg("Event rejected for media protection")
						return PSRecommendationSpam, nil
					}
					logger.Debug().Msg("event passed media protection check")
				}
			}
		}
	}
	logger.Debug().Msg("Event passed all checks, returning OK recommendation")
	return PSRecommendationOk, nil
}

func (ps *PolicyServer) HandleCheck(
	ctx context.Context,
	evtID id.EventID,
	pdu *event.Event,
	evaluator *PolicyEvaluator,
	redact bool,
) (res *PolicyServerResponse, err error) {
	ctx = zerolog.Ctx(ctx).With().
		Stringer("room_id", pdu.RoomID).
		Stringer("event_id", evtID).
		Logger().
		WithContext(ctx)
	log := zerolog.Ctx(ctx)
	rs := time.Now()
	r := ps.getCache(evtID, pdu)
	log.Trace().Dur("duration", time.Since(rs)).Interface("recommendation", r).Msg("fetched recommendation from cache")
	la := time.Now()
	r.Lock.Lock()
	log.Trace().Dur("duration", time.Since(la)).Msg("locked cache entry for event")
	defer r.Lock.Unlock()
	if r.Recommendation == "" {
		log.Trace().Any("event", pdu).Msg("Checking event received by policy server")
		rst := time.Now()
		rec, _ := ps.getRecommendation(ctx, pdu, evaluator)
		log.Trace().Dur("duration", time.Since(rst)).Msg("Recommendation check completed")
		r.Recommendation = rec
		if rec == PSRecommendationSpam {
			if redact {
				go func() {
					if _, err = evaluator.Bot.RedactEvent(context.WithoutCancel(ctx), pdu.RoomID, evtID); err != nil {
						log.Error().Err(err).Msg("Failed to redact event")
					}
				}()
			}
		}
	}
	r.LastAccessed = time.Now()
	log.Trace().Dur("duration", time.Since(rs)).Interface("event", pdu).Msg("Checked event")
	return &PolicyServerResponse{Recommendation: r.Recommendation}, nil
}
