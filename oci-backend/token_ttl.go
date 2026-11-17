package ocibackend

import (
	"fmt"
	"math"
	"time"

	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/vault/sdk/framework"
)

const maxTokenTTLSeconds = int64(math.MaxInt64) / int64(time.Second)

// Inspect supplied durations before the SDK truncates them to integer seconds.
// In particular, a negative fraction must not turn into the zero/default sentinel.
func validateTokenTTLInputs(data *framework.FieldData, allowZero bool, fields ...string) error {
	for _, field := range fields {
		raw, supplied := data.Raw[field]
		if !supplied {
			continue
		}
		switch value := raw.(type) {
		case float64:
			if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value {
				return fmt.Errorf("%s must use whole seconds", field)
			}
		case float32:
			if math.Trunc(float64(value)) != float64(value) {
				return fmt.Errorf("%s must use whole seconds", field)
			}
		}
		duration, err := parseutil.ParseDurationSecond(raw)
		if err != nil {
			return fmt.Errorf("invalid %s: %w", field, err)
		}
		if duration < 0 || (!allowZero && duration == 0) || duration%time.Second != 0 {
			return fmt.Errorf("%s must use positive whole seconds (request ttl=0 selects the default)", field)
		}
	}
	return nil
}

// Check before multiplication: stored configuration can predate write validation.
func tokenTTLDuration(seconds int, field string) (time.Duration, error) {
	if seconds <= 0 || int64(seconds) > maxTokenTTLSeconds {
		return 0, fmt.Errorf("%s must be between 1 and %d seconds", field, maxTokenTTLSeconds)
	}
	return time.Duration(seconds) * time.Second, nil
}

func validateTokenTTLPair(defaultTTL, maxTTL time.Duration) error {
	if defaultTTL <= 0 || maxTTL <= 0 || defaultTTL%time.Second != 0 || maxTTL%time.Second != 0 {
		return fmt.Errorf("default_ttl and max_ttl must be positive whole-second durations")
	}
	if defaultTTL > maxTTL {
		return fmt.Errorf("default_ttl must not exceed max_ttl")
	}
	return nil
}

func configuredTokenTTLs(config *federatedConfig) (time.Duration, time.Duration, error) {
	defaultTTL, err := tokenTTLDuration(config.DefaultTTL, "default_ttl")
	if err != nil {
		return 0, 0, err
	}
	maxTTL, err := tokenTTLDuration(config.MaxTTL, "max_ttl")
	if err != nil {
		return 0, 0, err
	}
	return defaultTTL, maxTTL, validateTokenTTLPair(defaultTTL, maxTTL)
}

// resolveTokenTTL keeps role defaults independent of backend policy, but no role
// can relax a backend or Vault ceiling. Vault's SystemView supplies the effective
// mount/system maximum. Zero means no additional limit in a synthetic SystemView.
func resolveTokenTTL(requestSeconds int, config *federatedConfig, role *roleEntry, vaultMax time.Duration) (time.Duration, time.Duration, error) {
	ttl, maxTTL, err := configuredTokenTTLs(config)
	if err != nil {
		return 0, 0, err
	}
	if role != nil {
		// Legacy zero role values inherit backend policy. New writes require
		// positive values; invalid stored policy must never silently issue tokens.
		if role.DefaultTTL < 0 || role.MaxTTL < 0 || role.DefaultTTL%time.Second != 0 || role.MaxTTL%time.Second != 0 {
			return 0, 0, fmt.Errorf("invalid stored role TTL")
		}
		if role.DefaultTTL > 0 && role.MaxTTL > 0 && role.DefaultTTL > role.MaxTTL {
			return 0, 0, fmt.Errorf("role default_ttl must not exceed max_ttl")
		}
		if role.DefaultTTL > 0 {
			ttl = role.DefaultTTL
		}
		if role.MaxTTL > 0 && role.MaxTTL < maxTTL {
			maxTTL = role.MaxTTL
		}
	}
	if requestSeconds != 0 {
		ttl, err = tokenTTLDuration(requestSeconds, "ttl")
		if err != nil {
			return 0, 0, err
		}
	}
	if vaultMax < 0 {
		return 0, 0, fmt.Errorf("invalid Vault maximum lease TTL")
	}
	if vaultMax > 0 && vaultMax < maxTTL {
		// OCI's rpst_exp is expressed in whole seconds; never round a ceiling up.
		maxTTL = vaultMax.Truncate(time.Second)
	}
	if maxTTL < time.Second {
		return 0, 0, fmt.Errorf("effective maximum TTL must be at least one second")
	}
	if ttl > maxTTL {
		ttl = maxTTL
	}
	return ttl, maxTTL, nil
}
