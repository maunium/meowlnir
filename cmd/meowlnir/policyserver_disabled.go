//go:build !goexperiment.jsonv2

package main

import (
	"net/http"

	"maunium.net/go/mautrix"
)

func (m *Meowlnir) PostMSC4284EventCheck(w http.ResponseWriter, r *http.Request) {
	mautrix.MUnrecognized.WithMessage("This Meowlnir wasn't compiled with jsonv2 for policy server support").Write(w)
}
