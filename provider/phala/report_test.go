package phala

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	nearai "github.com/nearai/inference-sdk/go"

	"github.com/BOTChainLabs/private-ai-go/core"
	"github.com/BOTChainLabs/private-ai-go/internal/tdx"
)

// Two genuine reports from inference.phala.com, on either side of a gateway
// release. attestation-nonce.json was fetched with the nonce in
// attestation-nonce.txt; the nonce of attestation.json is unknown.
func loadReport(t *testing.T, name string) *Report {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var r Report
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

func reportNonce(t *testing.T) string {
	t.Helper()
	return nonceFile(t, "attestation-nonce.txt")
}

func nonceFile(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// measured reads a genuine report's quote and replays its event log.
func measured(t *testing.T, r *Report) (QuoteResult, map[string]string) {
	t.Helper()
	raw, _ := hex.DecodeString(r.Attestation.Evidence.Quote)
	q, err := parseTDReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	events, err := tdx.ReplayRTMR3([]byte(r.Attestation.Evidence.EventLog), q.RTMR3)
	if err != nil {
		t.Fatal(err)
	}
	return q, events
}

// offlineQuote reads the measurements from the real quote bytes without
// checking Intel's signature, which needs network collateral and is covered
// by the live and cross-check tests.
func offlineQuote(tcb string) QuoteVerifier {
	return func(_ context.Context, q string) (QuoteResult, error) {
		raw, err := hex.DecodeString(q)
		if err != nil {
			return QuoteResult{}, err
		}
		r, err := parseTDReport(raw)
		r.TCBStatus = tcb
		return r, err
	}
}

var captured = time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)

func productionVerifier() *Verifier {
	return &Verifier{Quote: offlineQuote("UpToDate"), Workload: ProductionWorkload()}
}

// The DCAP verifier's TCB status and advisories are kept with the
// measurements read from the quote.
func TestDCAPQuoteVerifierKeepsAdvisories(t *testing.T) {
	r := loadReport(t, "attestation-nonce.json")
	raw, _ := hex.DecodeString(r.Attestation.Evidence.Quote)
	td, err := parseTDReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	dcap := func(context.Context, string) (nearai.QuoteVerificationResult, error) {
		return nearai.QuoteVerificationResult{TCBStatus: "OutOfDate", AdvisoryIDs: []string{"INTEL-SA-01312"}, ReportData: td.ReportData, RTMR3: td.RTMR3, MRConfigID: td.MRConfigID}, nil
	}
	q, err := dcapQuoteVerifier(dcap)(context.Background(), r.Attestation.Evidence.Quote)
	if err != nil {
		t.Fatal(err)
	}
	if q.TCBStatus != "OutOfDate" || !slices.Equal(q.AdvisoryIDs, []string{"INTEL-SA-01312"}) || !bytes.Equal(q.MRTD, td.MRTD) {
		t.Fatalf("quote %+v", q)
	}
}

func TestParseTDReportOnRealQuote(t *testing.T) {
	r := loadReport(t, "attestation-nonce.json")
	raw, _ := hex.DecodeString(r.Attestation.Evidence.Quote)
	td, err := parseTDReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	os := ProductionWorkload().OS[0]
	if hex.EncodeToString(td.MRTD) != os.MRTD || hex.EncodeToString(td.RTMR2) != os.RTMR2 {
		t.Fatalf("MRTD %x RTMR2 %x", td.MRTD, td.RTMR2)
	}
	if hex.EncodeToString(td.ReportData[:32]) != r.Attestation.ReportData {
		t.Fatal("report_data offset wrong")
	}
	if _, err := parseTDReport(raw[:100]); err == nil {
		t.Fatal("short quote accepted")
	}
}

// The full identity check on a genuine report, with its real nonce.
func TestVerifyRealReport(t *testing.T) {
	r := loadReport(t, "attestation-nonce.json")
	id, err := productionVerifier().VerifyReport(context.Background(), r, reportNonce(t), "inference.phala.com", captured)
	if err != nil {
		t.Fatal(err)
	}
	if id.KeysetDigest != "sha256:a036d8bba3204f9d51fa458d9adb0998af06c71154ad094e6fced9e9742b2f17" ||
		id.ComposeHash != "4dbdcd4f17786388a5c35d3847894f9f216c1e3a48331a435398808e1593587d" ||
		id.AppID != "fdb7a14e5a6675f752e2cb69c9067a98ca402918" ||
		id.TLSPins[0] != "32a2825658a7377a37d6b6e854627dd16bdd8abd82353259884eac7866229ea7" || len(id.KeysetJSON) == 0 {
		t.Fatalf("identity %+v", id)
	}
}

// The older report, from before the gateway release, passes the same
// production workload: releases do not need SDK changes. Its nonce is
// unknown, so this checks everything after the nonce binding.
func TestProductionWorkloadAcceptsBothReleases(t *testing.T) {
	r := loadReport(t, "attestation.json")
	raw, _ := hex.DecodeString(r.Attestation.Evidence.Quote)
	q, err := parseTDReport(raw)
	if err != nil {
		t.Fatal(err)
	}
	events, err := tdx.ReplayRTMR3([]byte(r.Attestation.Evidence.EventLog), q.RTMR3)
	if err != nil {
		t.Fatal(err)
	}
	if err := productionVerifier().checkWorkload(q, events); err != nil {
		t.Fatal(err)
	}
}

// The gateway Phala runs since 2026-11-06, captured on 2026-11-11 with its
// nonce: app 89c51ab8 on the dstack KMS on Base, on dstack OS 0.5.12.
func TestVerifyRealReportBaseKMS(t *testing.T) {
	r := loadReport(t, "attestation-2026-11-11.json")
	at := time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC)
	id, err := productionVerifier().VerifyReport(context.Background(), r, nonceFile(t, "attestation-2026-11-11-nonce.txt"), "inference.phala.com", at)
	if err != nil {
		t.Fatal(err)
	}
	if id.AppID != "89c51ab856bee41efe78c40309a4deb277a02a0f" ||
		id.ComposeHash != "66e91ac6c2325537851bc95fc0e4489df119b7b0204d27f2bae91ec1324ecf1f" || len(id.TLSPins) == 0 {
		t.Fatalf("identity %+v", id)
	}
}

// Each of Phala's deployments is accepted only as a whole: its app with its
// own KMS and OS build. The values of the two do not mix.
func TestProductionWorkloadBindsDeployments(t *testing.T) {
	oldQ, oldEv := measured(t, loadReport(t, "attestation-nonce.json"))      // fdb7a14e, Phala Cloud's KMS, OS 0.5
	newQ, newEv := measured(t, loadReport(t, "attestation-2026-11-11.json")) // 89c51ab8, the Base KMS, OS 0.5.12
	v := productionVerifier()
	for name, c := range map[string]struct {
		q  QuoteResult
		ev map[string]string
	}{"old deployment": {oldQ, oldEv}, "new deployment": {newQ, newEv}} {
		if err := v.checkWorkload(c.q, c.ev); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	with := func(ev map[string]string, kv ...string) map[string]string {
		out := maps.Clone(ev)
		for i := 0; i < len(kv); i += 2 {
			out[kv[i]] = kv[i+1]
		}
		return out
	}
	app, kms := "app-id", "key-provider"
	cases := []struct {
		name string
		q    QuoteResult
		ev   map[string]string
	}{
		{"new app on Phala Cloud's KMS", newQ, with(newEv, kms, oldEv[kms])},
		{"old app on the Base KMS", oldQ, with(oldEv, kms, newEv[kms])},
		{"new app and KMS on the old OS", oldQ, with(oldEv, app, newEv[app], kms, newEv[kms])},
		{"old app and KMS on the new OS", newQ, with(newEv, app, oldEv[app], kms, oldEv[kms])},
		{"new app on the old OS and KMS", oldQ, with(oldEv, app, newEv[app])},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := v.checkWorkload(c.q, c.ev)
			if err == nil || !strings.Contains(err.Error(), "not an accepted deployment") {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// A deployment with an empty field would accept anything there: it never
// matches, and New refuses it.
func TestIncompleteDeploymentNeverMatches(t *testing.T) {
	q, ev := measured(t, loadReport(t, "attestation-nonce.json"))
	w := ProductionWorkload()
	for i := range w.Deployments {
		w.Deployments[i].KeyProviders = nil
	}
	v := &Verifier{Quote: offlineQuote("UpToDate"), Workload: w}
	if err := v.checkWorkload(q, ev); err == nil {
		t.Fatal("a deployment without key providers matched")
	}
	if _, err := New(Options{APIKey: "k", Workload: &w}); err == nil {
		t.Fatal("New accepted a deployment without key providers")
	}
}

func TestVerifyRealReportRejects(t *testing.T) {
	nonce := reportNonce(t)
	cases := []struct {
		name   string
		edit   func(v *Verifier, r *Report, nonce *string)
		reason string
	}{
		{"wrong nonce", func(_ *Verifier, _ *Report, n *string) { *n = strings.Repeat("0", 64) }, "report_data"},
		{"revoked TCB", func(v *Verifier, _ *Report, _ *string) { v.Quote = offlineQuote("Revoked") }, "TCB status"},
		{"configuration needed", func(v *Verifier, _ *Report, _ *string) { v.Quote = offlineQuote("ConfigurationNeeded") }, "TCB status"},
		{"other OS build", func(v *Verifier, _ *Report, _ *string) { v.Workload.OS[0].RTMR1 = strings.Repeat("00", 48) }, "unknown OS build"},
		{"other app", func(v *Verifier, _ *Report, _ *string) { v.Workload.AppIDs = []string{"0000"} }, "unexpected app-id"},
		{"other KMS", func(v *Verifier, _ *Report, _ *string) { v.Workload.KeyProviders = []string{"00"} }, "unexpected key-provider"},
		{"compose not allowlisted", func(v *Verifier, _ *Report, _ *string) { v.Policy.ComposeHashes = []string{strings.Repeat("ab", 32)} }, "allowlist"},
		// The reviewer's attack: swap app_compose and the compose-hash
		// payload together. MRCONFIGID still binds the real compose.
		{"swapped compose", func(_ *Verifier, r *Report, _ *string) {
			evil := "EVIL COMPOSE"
			sum := sha256.Sum256([]byte(evil))
			r.Attestation.Evidence.EventLog = strings.Replace(r.Attestation.Evidence.EventLog,
				"4dbdcd4f17786388a5c35d3847894f9f216c1e3a48331a435398808e1593587d", hex.EncodeToString(sum[:]), 1)
			r.Attestation.Evidence.AppCompose = evil
		}, "MRCONFIGID"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, r, n := productionVerifier(), loadReport(t, "attestation-nonce.json"), nonce
			c.edit(v, r, &n)
			_, err := v.VerifyReport(context.Background(), r, n, "inference.phala.com", captured)
			if err == nil || !strings.Contains(err.Error(), c.reason) {
				t.Fatalf("err = %v, want it to mention %q", err, c.reason)
			}
		})
	}

	// A compose allowlist that lists the real compose passes.
	v := productionVerifier()
	v.Policy = core.Policy{ComposeHashes: []string{"4DBDCD4F17786388A5C35D3847894F9F216C1E3A48331A435398808E1593587D"}, AcceptedTCBStatuses: []string{"UpToDate"}}
	if _, err := v.VerifyReport(context.Background(), loadReport(t, "attestation-nonce.json"), nonce, "inference.phala.com", captured); err != nil {
		t.Fatal(err)
	}
}

// Each RTMR3 payload is bound to its digest, so a payload cannot be swapped
// while the replay still reaches the quote's RTMR3.
func TestReplayRTMR3BindsPayloads(t *testing.T) {
	r := loadReport(t, "attestation-nonce.json")
	raw, _ := hex.DecodeString(r.Attestation.Evidence.Quote)
	q, _ := parseTDReport(raw)
	log := r.Attestation.Evidence.EventLog

	swapped := strings.Replace(log, "fdb7a14e5a6675f752e2cb69c9067a98ca402918", "fdb7a14e5a6675f752e2cb69c9067a98ca402919", 1)
	if _, err := tdx.ReplayRTMR3([]byte(swapped), q.RTMR3); err == nil || !strings.Contains(err.Error(), "digest does not match") {
		t.Fatalf("swapped app-id payload: %v", err)
	}
	var events []map[string]any
	json.Unmarshal([]byte(log), &events)
	for _, e := range events {
		if e["event"] == "app-id" {
			events = append(events, e) // a second app-id event
			break
		}
	}
	dup, _ := json.Marshal(events)
	if _, err := tdx.ReplayRTMR3(dup, q.RTMR3); err == nil {
		t.Fatal("duplicate app-id event accepted")
	}
}

func TestParseKeysetRejectsAmbiguousMembers(t *testing.T) {
	for _, ks := range []string{
		`{"not_after":1,"NOT_AFTER":2,"receipt_signing_keys":[],"tls_public_keys":[]}`,
		`{"not_after":1,"extra":true,"receipt_signing_keys":[],"tls_public_keys":[]}`,
		`{"not_after":1,"receipt_signing_keys":[{"key_id":"a","Key_ID":"b","algo":"ed25519","public_key":"00"}],"tls_public_keys":[]}`,
		`{"receipt_signing_keys":[],"tls_public_keys":[]}`,
	} {
		if _, err := parseKeyset([]byte(ks)); err == nil {
			t.Errorf("parseKeyset(%s) accepted", ks)
		}
	}
}
