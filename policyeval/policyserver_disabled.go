//go:build !goexperiment.jsonv2 && !go1.27

package policyeval

import (
	"fmt"
)

func (ps *PolicyServer) PreSignEvents(ctx, createEvt, events any) (signed, failed int, err error) {
	return 0, 0, fmt.Errorf("not built with policy server support")
}
