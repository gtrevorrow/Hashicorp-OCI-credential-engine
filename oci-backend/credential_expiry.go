package ocibackend

import (
	"fmt"
	"time"
)

// OCI credential lifetime and Vault lease policy are different quantities.
// Unknown upstream expiry must never be manufactured from the requested TTL.
func reconcileCredentialExpiry(ttl, maxTTL time.Duration, expiresAt, now time.Time) (time.Duration, time.Duration, time.Duration, error) {
	if expiresAt.IsZero() {
		return ttl, maxTTL, 0, nil
	}
	remaining := expiresAt.Sub(now).Truncate(time.Second)
	if remaining < time.Second {
		return 0, 0, 0, fmt.Errorf("credential has less than one second of remaining lifetime")
	}
	if ttl > remaining {
		ttl = remaining
	}
	if maxTTL > remaining {
		maxTTL = remaining
	}
	return ttl, maxTTL, remaining, nil
}
