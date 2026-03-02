package protections

import (
	"time"
)

// useOrigin determines whether to use the event origin time or local time based on the dontTrustServer flag and the
// claimedOrigin time. If dontTrustServer is false or the claimed origin time is more than 1 hour in the future or past,
// it returns false, indicating local time should be used. Otherwise, it returns true.
func useOrigin(dontTrustServer bool, claimedOrigin time.Time) bool {
	if !dontTrustServer {
		return false
	}
	now := time.Now()
	return !(claimedOrigin.After(now.Add(1*time.Hour)) || claimedOrigin.Before(now.Add(-1*time.Hour)))
}
