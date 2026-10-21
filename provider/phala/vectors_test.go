package phala

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/BOTChainLabs/private-ai-go/internal/canon"
)

// Vectors from spec/test-vectors.md in Dstack-TEE/private-ai-gateway.
const (
	vecKeysetJCS    = `{"e2ee_public_keys":[{"algo":"x25519-aes-256-gcm-hkdf-sha256","key_id":"e2ee-1","public_key":"5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"}],"not_after":1800000000,"receipt_signing_keys":[{"algo":"ed25519","key_id":"receipt-1","public_key":"8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"}],"subject":"dstack-app://example-app","tls_public_keys":[{"domain":"api.example.com","spki_sha256":"c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"}]}`
	vecKeysetDigest = "sha256:53a5cd44b30dcc51999754c719f2628a041f174ecbf9662a6f8e898a10cd9371"
	vecNonce        = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	vecReportData   = "df2174d28130852b413646a3786927b93e94c11d770268b65def8bdba45cb49e"
	vecReportNull   = "0633919ca3f00e97bafaa3304278eb22420cc3ff0d19f87dfca2d3f7508150bc"
	vecReceiptPub   = "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"
	vecRequest      = `{"messages":[{"content":"hi","role":"user"}],"model":"demo-model"}`
	vecResponse     = `{"choices":[],"id":"chatcmpl-123"}`
	vecReceipt      = `{"api_version":"aci/1","chat_id":"chatcmpl-123","endpoint":"/v1/chat/completions","event_log":[{"body_hash":"sha256:94d809bf47380d8a2eab0eb6e126d4dda9364b0b4725cdf7ead52dd70b2aa87b","type":"request.received"},{"body_hash":"sha256:94d809bf47380d8a2eab0eb6e126d4dda9364b0b4725cdf7ead52dd70b2aa87b","type":"request.forwarded"},{"model_id":"demo-model","required":true,"result":"verified","session_id":"95ad1cb4dd25445808c2e9d116caf420b05703730b506395e8fc1ca6faeae28f","type":"upstream.verified"},{"body_hash":"sha256:dedfffe5b14d031b8e2c01996d021a15293cb7c63b56be7e4be9e89b6f0a5f61","type":"response.returned"}],"key_id":"receipt-1","method":"POST","model":"demo-model","receipt_id":"rcpt-0001","served_at":1750000000,"signature":"d5b005e093bde3b577faf270b7184b09e169cacb0ecb206b103bd2581f997db03da616175454b063323a23ac1dc68f1ce506c2a6eba8aa0561d5e724f0b80c03","workload_keyset_digest":"sha256:53a5cd44b30dcc51999754c719f2628a041f174ecbf9662a6f8e898a10cd9371"}`
)

var vecReceiptKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x02}, 32))

func TestKeysetDigestVector(t *testing.T) {
	// Same content, different encoding: member order and whitespace must not matter.
	pretty := `{
	  "subject": "dstack-app://example-app",
	  "not_after": 1800000000,
	  "tls_public_keys": [{"spki_sha256": "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0", "domain": "api.example.com"}],
	  "receipt_signing_keys": [{"public_key": "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394", "key_id": "receipt-1", "algo": "ed25519"}],
	  "e2ee_public_keys": [{"key_id": "e2ee-1", "algo": "x25519-aes-256-gcm-hkdf-sha256", "public_key": "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22"}]
	}`
	c, err := canon.Canonicalize([]byte(pretty))
	if err != nil {
		t.Fatal(err)
	}
	if string(c) != vecKeysetJCS {
		t.Fatalf("JCS mismatch:\n got %s\nwant %s", c, vecKeysetJCS)
	}
	d, err := KeysetDigest([]byte(pretty))
	if err != nil || d != vecKeysetDigest {
		t.Fatalf("digest = %s, %v; want %s", d, err, vecKeysetDigest)
	}
}

func TestReportDataVector(t *testing.T) {
	n := vecNonce
	if got := ExpectedReportData(vecKeysetDigest, &n); hex.EncodeToString(got[:]) != vecReportData {
		t.Fatalf("with nonce: %x", got)
	}
	if got := ExpectedReportData(vecKeysetDigest, nil); hex.EncodeToString(got[:]) != vecReportNull {
		t.Fatalf("null nonce: %x", got)
	}
}

func vecIdentity() *Identity {
	return &Identity{
		KeysetDigest: vecKeysetDigest,
		Keyset:       Keyset{ReceiptSigningKeys: []KeyEntry{{KeyID: "receipt-1", Algo: "ed25519", PublicKey: vecReceiptPub}}},
		Serving:      "aggregator",
	}
}

// resign edits the vector receipt and signs it again with the vector key.
func resign(t *testing.T, edit func(doc map[string]any)) []byte {
	t.Helper()
	v, err := canon.Decode([]byte(vecReceipt))
	if err != nil {
		t.Fatal(err)
	}
	doc := v.(map[string]any)
	delete(doc, "signature")
	edit(doc)
	signed, err := canon.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	doc["signature"] = hex.EncodeToString(ed25519.Sign(vecReceiptKey, signed))
	out, _ := json.Marshal(doc)
	return out
}

func TestVerifyReceiptVector(t *testing.T) {
	if hex.EncodeToString(vecReceiptKey.Public().(ed25519.PublicKey)) != vecReceiptPub {
		t.Fatal("seed does not produce the vector public key")
	}
	res, err := VerifyReceipt([]byte(vecReceipt), vecIdentity(), []byte(vecRequest), []byte(vecResponse))
	if err != nil {
		t.Fatalf("vector receipt rejected: %v", err)
	}
	if res.SessionID != "95ad1cb4dd25445808c2e9d116caf420b05703730b506395e8fc1ca6faeae28f" || res.ReceiptID != "rcpt-0001" {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestVerifyReceiptRejects(t *testing.T) {
	setEvent := func(typ, field string, val any) func(map[string]any) {
		return func(doc map[string]any) {
			for _, e := range doc["event_log"].([]any) {
				if ev := e.(map[string]any); ev["type"] == typ {
					ev[field] = val
				}
			}
		}
	}
	cases := []struct {
		name    string
		receipt []byte
		id      *Identity
		resp    string
		want    string
	}{
		{"response bytes changed", []byte(vecReceipt), vecIdentity(), `{"choices":[],"id":"chatcmpl-124"}`, "response hash"},
		{"signature tampered", []byte(strings.Replace(vecReceipt, `"served_at":1750000000`, `"served_at":1750000001`, 1)), vecIdentity(), vecResponse, "signature"},
		{"unknown key", resign(t, func(d map[string]any) { d["key_id"] = "other" }), vecIdentity(), vecResponse, "not in the established keyset"},
		{"other keyset", resign(t, func(d map[string]any) { d["workload_keyset_digest"] = "sha256:00" }), vecIdentity(), vecResponse, "names keyset"},
		{"upstream failed", resign(t, setEvent("upstream.verified", "result", "failed")), vecIdentity(), vecResponse, "upstream verification failed"},
		{"upstream not required", resign(t, setEvent("upstream.verified", "required", false)), vecIdentity(), vecResponse, "not required"},
		{"no upstream event", resign(t, func(d map[string]any) {
			var kept []any
			for _, e := range d["event_log"].([]any) {
				if e.(map[string]any)["type"] != "upstream.verified" {
					kept = append(kept, e)
				}
			}
			d["event_log"] = kept
		}), vecIdentity(), vecResponse, "no upstream.verified"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyReceipt(tc.receipt, tc.id, []byte(vecRequest), []byte(tc.resp))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want containing %q", err, tc.want)
			}
		})
	}
}

// §7.5 allows failed attempts before the upstream that served; one verified,
// required event is enough.
func TestVerifyReceiptToleratesFailedAttempts(t *testing.T) {
	receipt := resign(t, func(d map[string]any) {
		events := d["event_log"].([]any)
		attempt := map[string]any{"type": "upstream.verified", "result": "failed", "required": true, "model_id": "demo-model", "reason": "session expired"}
		d["event_log"] = append([]any{events[0], events[1], attempt}, events[2:]...)
	})
	if _, err := VerifyReceipt(receipt, vecIdentity(), []byte(vecRequest), []byte(vecResponse)); err != nil {
		t.Fatalf("receipt with a failed attempt before the verified one rejected: %v", err)
	}
}
