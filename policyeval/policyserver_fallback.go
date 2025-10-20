//go:build !goexperiment.jsonv2

package policyeval

import (
	"context"
	"errors"

	"maunium.net/go/mautrix/event"
)

func (ps *PolicyServer) HandleSign(
	ctx context.Context,
	evt any,
	clientEvt *event.Event,
	evaluator *PolicyEvaluator,
	redact bool,
	caller string,
) (signatures map[string]map[string]string, err error) {
	return nil, errors.New("this Meowlnir wasn't compiled with jsonv2 for policy server support")
}
