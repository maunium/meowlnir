//go:build !goexperiment.jsonv2

package main

import (
	"net/http"

	"maunium.net/go/mautrix"
)

func (m *Meowlnir) PostMSC4284LegacyEventCheck(w http.ResponseWriter, r *http.Request) {
	mautrix.MUnrecognized.WithMessage("This Meowlnir wasn't compiled with jsonv2 for policy server support").Write(w)
}

func (m *Meowlnir) PostMSC4284LegacySign(w http.ResponseWriter, r *http.Request) {
	mautrix.MUnrecognized.WithMessage("This Meowlnir wasn't compiled with jsonv2 for policy server support").Write(w)
}

func (m *Meowlnir) PostPolicyServerSign(w http.ResponseWriter, r *http.Request) {
	mautrix.MUnrecognized.WithMessage("This Meowlnir wasn't compiled with jsonv2 for policy server support").Write(w)
}
