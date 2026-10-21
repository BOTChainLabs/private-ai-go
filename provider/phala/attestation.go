// Package phala verifies and calls Phala's confidential inference gateway
// under the ACI spec (aci/1):
// https://github.com/Dstack-TEE/private-ai-gateway/blob/main/spec/aci.md
package phala

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/BOTChainLabs/private-ai-go/core"
	"github.com/BOTChainLabs/private-ai-go/internal/canon"
	"github.com/BOTChainLabs/private-ai-go/internal/tdx"
)

const (
	apiVersion      = "aci/1"
	reportPurpose   = "aci.report_data.v1"
	maxKeysetWindow = 400 * 24 * time.Hour // reject implausibly distant not_after (spec §3.1)
)

// Report is the response of GET /v1/aci/attestation (spec §4.1).
type Report struct {
	APIVersion           string `json:"api_version"`
	WorkloadKeysetDigest string `json:"workload_keyset_digest"`
	Attestation          struct {
		TEEType string `json:"tee_type"`
		// Kept raw: the digest is computed over its canonical form.
		WorkloadKeyset   json.RawMessage `json:"workload_keyset"`
		ReportData       string          `json:"report_data"`
		SourceProvenance struct {
			RepoURL     *string `json:"repo_url"`
			RepoCommit  *string `json:"repo_commit"`
			ImageDigest *string `json:"image_digest"`
		} `json:"source_provenance"`
		Evidence struct {
			Quote      string `json:"quote"`
			EventLog   string `json:"event_log"`
			AppCompose string `json:"app_compose"`
		} `json:"evidence"`
	} `json:"attestation"`
	ServiceCapabilities struct {
		Serving string `json:"serving"`
	} `json:"service_capabilities"`
}

// Keyset is the workload keyset (spec §3.1).
type Keyset struct {
	Subject            *string    `json:"subject"`
	NotAfter           int64      `json:"not_after"`
	ReceiptSigningKeys []KeyEntry `json:"receipt_signing_keys"`
	TLSPublicKeys      []TLSKey   `json:"tls_public_keys"`
}

type KeyEntry struct {
	KeyID     string `json:"key_id"`
	Algo      string `json:"algo"`
	PublicKey string `json:"public_key"`
}

type TLSKey struct {
	SPKISHA256 string `json:"spki_sha256"`
	Domain     string `json:"domain"`
}

// Identity is an established service identity: the result of a successful
// preflight. Everything sent to the service afterwards is bound to it.
type Identity struct {
	KeysetDigest string
	Keyset       Keyset
	// KeysetJSON is the canonical keyset, kept so receipts can be
	// re-verified offline.
	KeysetJSON json.RawMessage
	NotAfter   time.Time
	// TLSPins are the hex SHA-256 SPKI digests the keyset allows for the
	// host. More than one can be listed while a TLS key rotates.
	TLSPins     []string
	ComposeHash string
	AppID       string
	OSImageHash string
	TCBStatus   string
	Serving     string
	RepoURL     string
	RepoCommit  string
}

// Verifier establishes service identities from attestation reports.
type Verifier struct {
	Quote    QuoteVerifier
	Workload Workload
	Policy   core.Policy
}

// KeysetDigest computes "sha256:" + hex(sha256(JCS(keyset))) (spec §3.1).
func KeysetDigest(rawKeyset []byte) (string, error) {
	c, err := canon.Canonicalize(rawKeyset)
	if err != nil {
		return "", fmt.Errorf("canonicalize keyset: %w", err)
	}
	sum := sha256.Sum256(c)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Statement builds the attestation statement (spec §3.2). A nil nonce yields
// the unchallenged form, which proves binding but not freshness.
func Statement(keysetDigest string, nonce *string) []byte {
	n := "null"
	if nonce != nil {
		n = `"` + *nonce + `"`
	}
	return []byte(`{"keyset_digest":"` + keysetDigest + `","nonce":` + n + `,"purpose":"` + reportPurpose + `"}`)
}

// ExpectedReportData is sha256(statement) (spec §3.2).
func ExpectedReportData(keysetDigest string, nonce *string) [32]byte {
	return sha256.Sum256(Statement(keysetDigest, nonce))
}

// VerifyReport runs the workload identity checks of spec §9.1 for a report
// fetched with nonce, to be used over host.
func (v *Verifier) VerifyReport(ctx context.Context, rep *Report, nonce, host string, now time.Time) (*Identity, error) {
	if rep.APIVersion != apiVersion {
		return nil, fmt.Errorf("unsupported api_version %q", rep.APIVersion)
	}
	if rep.Attestation.TEEType != "tdx" {
		return nil, fmt.Errorf("unsupported tee_type %q", rep.Attestation.TEEType)
	}
	ev := rep.Attestation.Evidence

	// Binding: keyset -> digest -> statement -> report_data.
	keysetJSON, err := canon.Canonicalize(rep.Attestation.WorkloadKeyset)
	if err != nil {
		return nil, fmt.Errorf("canonicalize keyset: %w", err)
	}
	sum := sha256.Sum256(keysetJSON)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if digest != rep.WorkloadKeysetDigest {
		return nil, fmt.Errorf("keyset digest mismatch: computed %s, served %s", digest, rep.WorkloadKeysetDigest)
	}
	ks, err := parseKeyset(keysetJSON)
	if err != nil {
		return nil, err
	}
	want := ExpectedReportData(digest, &nonce)
	if rep.Attestation.ReportData != hex.EncodeToString(want[:]) {
		return nil, fmt.Errorf("report_data does not bind the keyset and nonce")
	}

	// Hardware: a genuine, non-debug quote on an accepted TCB that carries
	// the same report_data, zero-padded to 64 bytes.
	q, err := v.Quote(ctx, ev.Quote)
	if err != nil {
		return nil, fmt.Errorf("verify quote: %w", err)
	}
	if q.DebugEnabled {
		return nil, fmt.Errorf("quote comes from a debug TD")
	}
	if !v.Policy.AcceptsTCB(q.TCBStatus) {
		return nil, fmt.Errorf("TCB status %q is not accepted (accepted: %v)", q.TCBStatus, v.Policy.TCBStatuses())
	}
	if len(q.ReportData) != 64 || !bytes.Equal(q.ReportData[:32], want[:]) || !bytes.Equal(q.ReportData[32:], make([]byte, 32)) {
		return nil, fmt.Errorf("quote report_data does not match the attestation statement")
	}

	// Which code: the booted compose is bound by MRCONFIGID (set at launch,
	// not changeable by the guest) and by the measured compose-hash event;
	// the OS, app and key provider must be the expected workload.
	composeSum := sha256.Sum256([]byte(ev.AppCompose))
	composeHash := hex.EncodeToString(composeSum[:])
	wantConfig := append(append([]byte{0x01}, composeSum[:]...), make([]byte, 15)...)
	if !bytes.Equal(q.MRConfigID, wantConfig) {
		return nil, fmt.Errorf("MRCONFIGID does not bind app_compose")
	}
	events, err := replayRTMR3(ev.EventLog, q.RTMR3)
	if err != nil {
		return nil, err
	}
	if events["compose-hash"] != composeHash {
		return nil, fmt.Errorf("measured compose-hash does not match app_compose")
	}
	if err := v.checkWorkload(q, events); err != nil {
		return nil, err
	}
	if !v.Policy.AcceptsCompose(composeHash) {
		return nil, fmt.Errorf("compose %s is not in the policy's allowlist", composeHash)
	}

	// Expiry.
	notAfter := time.Unix(ks.NotAfter, 0)
	if !now.Before(notAfter) {
		return nil, fmt.Errorf("keyset expired at %s", notAfter.UTC())
	}
	if notAfter.Sub(now) > maxKeysetWindow {
		return nil, fmt.Errorf("keyset not_after %s is implausibly distant", notAfter.UTC())
	}

	// Provenance is recorded; the workload checks above are what bind code.
	prov := rep.Attestation.SourceProvenance
	hasRepo := prov.RepoURL != nil && *prov.RepoURL != "" && prov.RepoCommit != nil && *prov.RepoCommit != ""
	hasImage := prov.ImageDigest != nil && *prov.ImageDigest != ""
	if !hasRepo && !hasImage {
		return nil, fmt.Errorf("report has no source provenance")
	}

	// Channel: the SPKIs to pin for this host. An entry without a domain
	// applies to every host (spec §3.1).
	var pins []string
	for _, k := range ks.TLSPublicKeys {
		if k.Domain == "" || strings.EqualFold(k.Domain, host) {
			pins = append(pins, strings.ToLower(k.SPKISHA256))
		}
	}
	if len(pins) == 0 {
		return nil, fmt.Errorf("keyset lists no TLS key for %s", host)
	}
	if !slices.ContainsFunc(ks.ReceiptSigningKeys, func(k KeyEntry) bool { return k.Algo == "ed25519" }) {
		return nil, fmt.Errorf("keyset has no ed25519 receipt signing key")
	}

	id := &Identity{
		KeysetDigest: digest,
		Keyset:       ks,
		KeysetJSON:   keysetJSON,
		NotAfter:     notAfter,
		TLSPins:      pins,
		ComposeHash:  composeHash,
		AppID:        events["app-id"],
		OSImageHash:  events["os-image-hash"],
		TCBStatus:    q.TCBStatus,
		Serving:      rep.ServiceCapabilities.Serving,
	}
	if hasRepo {
		id.RepoURL, id.RepoCommit = *prov.RepoURL, *prov.RepoCommit
	}
	return id, nil
}

// checkWorkload compares the measurements with the expected workload. The
// errors carry the observed values, so a new release is easy to recognize.
func (v *Verifier) checkWorkload(q QuoteResult, events map[string]string) error {
	w := v.Workload
	if err := tdx.CheckOS(q.measurements(), w.OS); err != nil {
		return err
	}
	return tdx.App{AppIDs: w.AppIDs, KeyProviders: w.KeyProviders, KMSMeasurements: w.KMSMeasurements}.Check(events)
}

// dstackEvent is the event type of dstack's RTMR3 runtime events.
const dstackEvent = tdx.DstackEvent

func replayRTMR3(eventLog string, quoteRTMR3 []byte) (map[string]string, error) {
	return tdx.ReplayRTMR3([]byte(eventLog), quoteRTMR3)
}

// keysetMembers is the fixed keyset shape (spec §3.1, Appendix B).
var keysetMembers = []string{"subject", "not_after", "receipt_signing_keys", "e2ee_public_keys", "tls_public_keys"}

// parseKeyset reads a canonical keyset. encoding/json matches member names
// case-insensitively, so names that differ from the spec only by case are
// rejected first: otherwise the parsed keys could differ from the hashed
// ones.
func parseKeyset(canonical []byte) (Keyset, error) {
	v, err := canon.Decode(canonical)
	if err != nil {
		return Keyset{}, fmt.Errorf("parse keyset: %w", err)
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return Keyset{}, fmt.Errorf("keyset is not an object")
	}
	for k := range obj {
		if !slices.Contains(keysetMembers, k) {
			return Keyset{}, fmt.Errorf("keyset has unknown member %q", k)
		}
	}
	entryMembers := []string{"key_id", "algo", "public_key", "spki_sha256", "domain"}
	for _, list := range []string{"receipt_signing_keys", "e2ee_public_keys", "tls_public_keys"} {
		entries, _ := obj[list].([]any)
		for _, e := range entries {
			entry, ok := e.(map[string]any)
			if !ok {
				return Keyset{}, fmt.Errorf("keyset %s entry is not an object", list)
			}
			for k := range entry {
				for _, m := range entryMembers {
					if k != m && strings.EqualFold(k, m) {
						return Keyset{}, fmt.Errorf("keyset %s entry has ambiguous member %q", list, k)
					}
				}
			}
		}
	}
	if _, ok := obj["not_after"].(json.Number); !ok {
		return Keyset{}, fmt.Errorf("keyset has no not_after")
	}
	var ks Keyset
	if err := json.Unmarshal(canonical, &ks); err != nil {
		return Keyset{}, fmt.Errorf("parse keyset: %w", err)
	}
	return ks, nil
}
