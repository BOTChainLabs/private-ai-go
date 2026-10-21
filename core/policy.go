package core

import (
	"slices"
	"strings"
)

// Policy decides which attested deployments a provider accepts, beyond the
// provider's built-in checks.
type Policy struct {
	// AcceptedTCBStatuses lists the Intel TCB statuses accepted for a TEE.
	// Empty means UpToDate and OutOfDate; revoked platforms and platforms
	// that need configuration changes are refused.
	AcceptedTCBStatuses []string
	// ComposeHashes, when set, accepts only deployments whose measured
	// app-compose hash (hex) is listed. Empty accepts any compose the
	// provider's identity checks allow.
	ComposeHashes []string
}

var defaultTCBStatuses = []string{"UpToDate", "OutOfDate"}

// TCBStatuses returns the accepted TCB statuses, applying the default.
func (p Policy) TCBStatuses() []string {
	if len(p.AcceptedTCBStatuses) == 0 {
		return slices.Clone(defaultTCBStatuses)
	}
	return slices.Clone(p.AcceptedTCBStatuses)
}

func (p Policy) AcceptsTCB(status string) bool {
	return slices.Contains(p.TCBStatuses(), status)
}

func (p Policy) AcceptsCompose(hash string) bool {
	if len(p.ComposeHashes) == 0 {
		return true
	}
	return slices.ContainsFunc(p.ComposeHashes, func(h string) bool { return strings.EqualFold(h, hash) })
}
