package core

import (
	"slices"
	"strings"
)

// Policy decides which attested deployments a provider accepts, beyond the
// provider's built-in checks.
type Policy struct {
	// AcceptedTCBStatuses lists the Intel TCB statuses accepted for a TEE.
	// Empty means UpToDate and OutOfDate; revoked platforms, and platforms
	// that need configuration changes or software hardening, are refused.
	//
	// OutOfDate means the platform lacks the fixes of the Intel advisories
	// that Evidence.AdvisoryIDs names. It is accepted by default because
	// providers' platforms run behind Intel's TCB recoveries (on 2026-11-11
	// NEAR AI's gateway was OutOfDate, for INTEL-SA-01192, -01245, -01312
	// and -01313), and refusing it would stop every call to them until they
	// patch. Set []string{"UpToDate"} to refuse it.
	AcceptedTCBStatuses []string
	// ComposeHashes, when set, accepts only deployments whose measured
	// app-compose hash (hex) is listed. Empty accepts any compose the
	// provider's identity checks allow. A self-hosted gateway pins its
	// releases in GatewayIdentity.ComposeHashes instead, and refuses this.
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
