package policyeval

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/rs/zerolog"
	"go.mau.fi/util/exmaps"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type protectionRegistryItem struct {
	name     string
	safe     bool
	priority int
	factory  func() any
}

var protectionsRegistry = map[string]protectionRegistryItem{}

func RegisterProtection[T any](name string, safe bool, priority int) {
	checkType[T]()
	protectionsRegistry[name] = protectionRegistryItem{
		name:     name,
		safe:     safe,
		priority: priority,
		factory:  protectionFactory[T](),
	}
}

var getProtectionOrder = sync.OnceValue(func() (out []string) {
	sortProtection := func(item protectionRegistryItem, item2 protectionRegistryItem) int {
		return cmp.Or(cmp.Compare(item2.priority, item.priority), cmp.Compare(item.name, item2.name))
	}
	sortedProtections := slices.SortedFunc(maps.Values(protectionsRegistry), sortProtection)
	out = make([]string, len(sortedProtections))
	for i, item := range sortedProtections {
		out[i] = item.name
	}
	return out
})

var getSafeProtections = sync.OnceValue(func() (out exmaps.Set[string]) {
	out = make(exmaps.Set[string])
	for name, item := range protectionsRegistry {
		if item.safe {
			out.Add(name)
		}
	}
	return out
})

func checkType[T any]() {
	var zero T
	if _, ok := any(&zero).(Protection); !ok {
		panic(fmt.Sprintf("%T does not implement Protection", zero))
	}
}

func protectionFactory[T any]() func() any {
	return func() any {
		var zero T
		return &zero
	}
}

// ShouldExecuteProtections determines if protections should be executed for a given event.
func (pe *PolicyEvaluator) ShouldExecuteProtections(ctx context.Context, evt *event.Event, isPolicyServer bool) bool {
	if pe.rawProtections == nil || evt.Sender == pe.Bot.UserID || pe.Admins.Has(evt.Sender) {
		return false
	}
	if !isPolicyServer {
		sig, err := pe.DB.PSSignature.Get(ctx, evt.ID)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Stringer("room_id", evt.RoomID).
				Stringer("event_id", evt.ID).
				Msg("Failed to check if received event was signed by policy server")
		} else if sig != nil && sig.Signature != "" {
			// This has already been approved by us
			return false
		}
	}
	powerLevels, err := pe.getPowerLevels(ctx, evt.RoomID)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Stringer("room_id", evt.RoomID).
			Stringer("event_id", evt.ID).
			Msg("failed to get power levels for protection execution check; assuming not exempt")
		return true
	}
	if powerLevels == nil {
		// No known power levels, assume not exempt
		return true
	}
	// If this user can issue kicks we assume they're a room moderator and thus exempt.
	// TODO: custom exemption levels per protection
	return powerLevels.GetUserLevel(evt.Sender) < powerLevels.Kick()
}

type ProtectionParams struct {
	Eval        *PolicyEvaluator
	Evt         *event.Event
	Policy      bool
	IsOrigin    bool
	ParseFailed bool
}

func (p *ProtectionParams) SendNotice(ctx context.Context, message string, args ...any) id.EventID {
	return p.Eval.sendNotice(ctx, message, args...)
}

// Protection is an interface that defines the minimum exposed functionality required to define a protection.
// All protection definitions must implement this interface in order to be used.
type Protection interface {
	// Execute runs the current protection, returning an error if it fails.
	// If Meowlnir is running in a dry context, or the policy server is invoking this protection, the final
	// argument should be true, after which the response will indicate true if an external action should be performed
	// or the event blocked.
	Execute(ctx context.Context, p ProtectionParams) (bool, error)
}

func (pe *PolicyEvaluator) orderedProtections(yield func(string, Protection) bool) {
	for _, name := range getProtectionOrder() {
		item, ok := pe.rawProtections[name]
		if !ok {
			continue
		}
		if !yield(name, item) {
			return
		}
	}
}
