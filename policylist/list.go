package policylist

import (
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
	"unsafe"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.mau.fi/util/glob"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type dplNode struct {
	*Policy
	prev *dplNode
	next *dplNode
}

const hashSize = sha256.Size

var sha256Base64Length = base64.StdEncoding.EncodedLen(hashSize)

// List represents the list of rules for a single entity type.
//
// Policies are split into literal rules and dynamic rules. Literal rules are stored in a map for fast matching,
// while dynamic rules are glob patterns and are evaluated one by one for each query.
type List struct {
	matchDuration prometheus.Observer
	byStateKey    map[string]*dplNode
	byEntity      map[string]*dplNode
	byEntityHash  map[[hashSize]byte]*dplNode
	dynamicHead   *dplNode
	lock          sync.RWMutex
}

func NewList(roomID id.RoomID, entityType string) *List {
	return &List{
		matchDuration: matchDuration.WithLabelValues(roomID.String(), entityType),
		byStateKey:    make(map[string]*dplNode),
		byEntity:      make(map[string]*dplNode),
		byEntityHash:  make(map[[hashSize]byte]*dplNode),
	}
}

func typeQuality(evtType event.Type) int {
	switch evtType {
	case event.StatePolicyUser, event.StatePolicyRoom, event.StatePolicyServer:
		return 5
	case event.StateLegacyPolicyUser, event.StateLegacyPolicyRoom, event.StateLegacyPolicyServer:
		return 4
	case event.StateUnstablePolicyUser, event.StateUnstablePolicyRoom, event.StateUnstablePolicyServer:
		return 3
	default:
		return 0
	}
}

func (l *List) removeFromLinkedList(node *dplNode) {
	if l.dynamicHead == node {
		l.dynamicHead = node.next
	}
	if node.prev != nil {
		node.prev.next = node.next
	}
	if node.next != nil {
		node.next.prev = node.prev
	}
}

func (l *List) Add(value *Policy) (*Policy, bool) {
	l.lock.Lock()
	defer l.lock.Unlock()
	existing, ok := l.byStateKey[value.StateKey]
	if ok {
		if typeQuality(existing.Type) > typeQuality(value.Type) {
			// There's an existing policy with the same state key, but a newer event type, ignore this one.
			return nil, false
		} else if existing.EntityOrHash() == value.EntityOrHash() {
			oldPolicy := existing.Policy
			// The entity in the policy didn't change, just update the policy.
			existing.Policy = value
			return oldPolicy, true
		}
		// There's an existing event with the same state key, but the entity changed, remove the old node.
		l.removeFromLinkedList(existing)
		if existing.Entity != "" {
			delete(l.byEntity, existing.Entity)
		}
		if existing.EntityHash != nil {
			delete(l.byEntityHash, *existing.EntityHash)
		}
	}
	node := &dplNode{Policy: value}
	l.byStateKey[value.StateKey] = node
	if !value.Ignored {
		if value.Entity != "" {
			l.byEntity[value.Entity] = node
		}
		if value.EntityHash != nil {
			l.byEntityHash[*value.EntityHash] = node
		}
	}
	if _, isStatic := value.Pattern.(glob.ExactGlob); value.Entity != "" && !isStatic && !value.Ignored {
		if l.dynamicHead != nil {
			node.next = l.dynamicHead
			l.dynamicHead.prev = node
		}
		l.dynamicHead = node
	}
	if existing != nil {
		return existing.Policy, true
	}
	return nil, true
}

func (l *List) Remove(eventType event.Type, stateKey string) *Policy {
	l.lock.Lock()
	defer l.lock.Unlock()
	if value, ok := l.byStateKey[stateKey]; ok && eventType == value.Type {
		l.removeFromLinkedList(value)
		if entValue, ok := l.byEntity[value.Entity]; ok && entValue == value && value.Entity != "" {
			delete(l.byEntity, value.Entity)
		}
		if value.EntityHash != nil {
			if entHashValue, ok := l.byEntityHash[*value.EntityHash]; ok && entHashValue == value {
				delete(l.byEntityHash, *value.EntityHash)
			}
		}
		delete(l.byStateKey, stateKey)
		return value.Policy
	}
	return nil
}

var matchDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name: "meowlnir_policylist_match_duration_nanoseconds",
	Help: "Time taken to evaluate an entity against all policies",
	Buckets: []float64{
		// 1µs - 100µs
		1_000, 5_000, 10_000, 25_000, 50_000, 75_000, 100_000,
		// 250µs - 10ms
		250_000, 500_000, 750_000, 1_000_000, 5_000_000, 10_000_000,
	},
}, []string{"policy_list", "entity_type"})

func sha256String(entity string) [hashSize]byte {
	return sha256.Sum256(unsafe.Slice(unsafe.StringData(entity), len(entity)))
}

func (l *List) Match(entity string) (output Match) {
	if entity == "" {
		return
	}
	l.lock.RLock()
	defer l.lock.RUnlock()
	start := time.Now()
	if value, ok := l.byEntity[entity]; ok {
		output = Match{value.Policy}
	}
	if value, ok := l.byEntityHash[sha256String(entity)]; ok {
		output = append(output, value.Policy)
	}
	for item := l.dynamicHead; item != nil; item = item.next {
		if !item.Ignored && item.Pattern.Match(entity) {
			output = append(output, item.Policy)
		}
	}
	l.matchDuration.Observe(float64(time.Since(start)))
	return
}
