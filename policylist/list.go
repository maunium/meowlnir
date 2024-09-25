package policylist

import (
	"sync"
	"time"

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

// List represents the list of rules for a single entity type.
//
// Policies are split into literal rules and dynamic rules. Literal rules are stored in a map for fast matching,
// while dynamic rules are glob patterns and are evaluated one by one for each query.
type List struct {
	matchDuration prometheus.Observer
	byStateKey    map[string]*dplNode
	byEntity      map[string]*dplNode
	dynamicHead   *dplNode
	lock          sync.RWMutex
}

func NewList(roomID id.RoomID, entityType string) *List {
	return &List{
		matchDuration: matchDuration.WithLabelValues(roomID.String(), entityType),
		byStateKey:    make(map[string]*dplNode),
		byEntity:      make(map[string]*dplNode),
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
		} else if existing.Entity == value.Entity {
			oldPolicy := existing.Policy
			// The entity in the policy didn't change, just update the policy.
			existing.Policy = value
			return oldPolicy, true
		}
		// There's an existing event with the same state key, but the entity changed, remove the old node.
		l.removeFromLinkedList(existing)
		delete(l.byEntity, existing.Entity)
	}
	node := &dplNode{Policy: value}
	l.byStateKey[value.StateKey] = node
	l.byEntity[value.Entity] = node
	if _, isStatic := value.Pattern.(glob.ExactGlob); !isStatic {
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
		if entValue, ok := l.byEntity[value.Entity]; ok && entValue == value {
			delete(l.byEntity, value.Entity)
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

func (l *List) Match(entity string) (output Match) {
	l.lock.RLock()
	defer l.lock.RUnlock()
	start := time.Now()
	if value, ok := l.byEntity[entity]; ok {
		output = Match{value.Policy}
	}
	for item := l.dynamicHead; item != nil; item = item.next {
		if item.Pattern.Match(entity) {
			output = append(output, item.Policy)
		}
	}
	l.matchDuration.Observe(float64(time.Since(start)))
	return
}
