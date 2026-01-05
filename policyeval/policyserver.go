package policyeval

import (
	"slices"
	"sync"
	"time"

	"go.mau.fi/util/exsync"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

type psCacheEntry struct {
	Recommendation PSRecommendation
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

func NewPolicyServer(fed *federation.Client, serverAuth *federation.ServerAuth, signingKey *federation.SigningKey) *PolicyServer {
	return &PolicyServer{
		eventCache:     make(map[id.EventID]*psCacheEntry),
		redactionCache: exsync.NewSet[id.EventID](),
		Federation:     fed,
		ServerAuth:     serverAuth,
		CacheMaxSize:   1000,
		CacheMaxAge:    5 * time.Minute,
		SigningKey:     signingKey,
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

type LegacyPolicyServerResponse struct {
	Recommendation PSRecommendation `json:"recommendation"`
}

func (ps *PolicyServer) HandleLegacyCachedCheck(evtID id.EventID) *LegacyPolicyServerResponse {
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
	return &LegacyPolicyServerResponse{Recommendation: r.Recommendation}
}
