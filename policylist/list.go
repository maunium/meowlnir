package policylist

import (
	"sync"

	"go.mau.fi/util/glob"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// Policy represents a single moderation policy event with the relevant data parsed out.
type Policy struct {
	*event.ModPolicyContent
	Pattern glob.Glob

	StateKey  string
	Sender    id.UserID
	Type      event.Type
	Timestamp int64
	ID        id.EventID
}

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
	keys        map[string]*dplNode
	static      map[string]*Policy
	dynamicHead *dplNode
	lock        sync.RWMutex
}

func NewList() *List {
	return &List{
		keys:   make(map[string]*dplNode),
		static: make(map[string]*Policy),
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

func (l *List) removeLL(node *dplNode) {
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
	existing, ok := l.keys[value.StateKey]
	if ok {
		if typeQuality(existing.Type) > typeQuality(value.Type) {
			// There's an existing policy with the same state key, but a newer event type, ignore this one.
			return nil, false
		} else if existing.Entity == value.Entity {
			// The entity in the policy didn't change, just update the policy.
			existing.Policy = value
			return existing.Policy, true
		}
		// There's an existing event with the same state key, but the entity changed, remove the old node.
		l.removeLL(existing)
		delete(l.static, existing.Entity)
	}
	node := &dplNode{Policy: value}
	l.keys[value.StateKey] = node
	if _, isStatic := value.Pattern.(glob.ExactGlob); isStatic {
		l.static[value.Entity] = value
	} else {
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
	if value, ok := l.keys[stateKey]; ok && eventType == value.Type {
		l.removeLL(value)
		delete(l.static, value.Entity)
		delete(l.keys, stateKey)
		return value.Policy
	}
	return nil
}

func (l *List) Match(entity string) *Policy {
	l.lock.RLock()
	defer l.lock.RUnlock()
	if value, ok := l.static[entity]; ok {
		return value
	}
	return l.matchDynamicUnlocked(entity)
}

func (l *List) MatchLiteral(entity string) *Policy {
	l.lock.RLock()
	value := l.static[entity]
	l.lock.RUnlock()
	return value
}

func (l *List) MatchDynamic(entity string) *Policy {
	l.lock.RLock()
	defer l.lock.RUnlock()
	return l.matchDynamicUnlocked(entity)
}

func (l *List) matchDynamicUnlocked(entity string) *Policy {
	for item := l.dynamicHead; item != nil; item = item.next {
		if item.Pattern.Match(entity) {
			return item.Policy
		}
	}
	return nil
}
