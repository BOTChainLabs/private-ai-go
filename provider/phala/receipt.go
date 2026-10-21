package phala

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/BOTChainLabs/private-ai-go/internal/canon"
)

// ReceiptResult is the useful content of a verified receipt.
type ReceiptResult struct {
	ReceiptID string
	ChatID    string
	SessionID string
}

// BodyHash is the ACI digest encoding of raw bytes.
func BodyHash(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// VerifyReceipt checks a receipt against an established identity and the
// exact request and response bytes (spec §9.3). Behind an aggregator it also
// requires a verified, mandatory upstream TEE session.
func VerifyReceipt(raw []byte, id *Identity, reqBody, respBody []byte) (*ReceiptResult, error) {
	v, err := canon.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("parse receipt: %w", err)
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("receipt is not an object")
	}

	// 1. Signature over the canonical form without "signature".
	sigHex, _ := doc["signature"].(string)
	keyID, _ := doc["key_id"].(string)
	delete(doc, "signature")
	signed, err := canon.Marshal(doc)
	if err != nil {
		return nil, err
	}
	pub, err := receiptKey(id, keyID)
	if err != nil {
		return nil, err
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("malformed receipt signature")
	}
	if !ed25519.Verify(pub, signed, sig) {
		return nil, fmt.Errorf("receipt signature does not verify")
	}

	// 2. Document binds the established keyset.
	if doc["api_version"] != apiVersion {
		return nil, fmt.Errorf("unsupported receipt api_version %v", doc["api_version"])
	}
	if doc["workload_keyset_digest"] != id.KeysetDigest {
		return nil, fmt.Errorf("receipt names keyset %v, established %s", doc["workload_keyset_digest"], id.KeysetDigest)
	}

	// 3-5. Events: exact bytes in and out, and the upstream outcome.
	events, _ := doc["event_log"].([]any)
	if len(events) == 0 {
		return nil, fmt.Errorf("receipt has no events")
	}
	res := &ReceiptResult{}
	res.ReceiptID, _ = doc["receipt_id"].(string)
	res.ChatID, _ = doc["chat_id"].(string)

	// Several upstream.verified events may appear: failed attempts before
	// the one that served (§7.5). One must be verified; all must be
	// required, since every request carries aci_verified.
	var sawRequest, sawResponse, verifiedUpstream bool
	var upstreamFailure any = "no upstream.verified event"
	for i, e := range events {
		ev, _ := e.(map[string]any)
		switch ev["type"] {
		case "request.received":
			if i != 0 {
				return nil, fmt.Errorf("request.received is not the first event")
			}
			if ev["body_hash"] != BodyHash(reqBody) {
				return nil, fmt.Errorf("receipt request hash does not match the bytes sent")
			}
			sawRequest = true
		case "response.returned":
			if ev["body_hash"] != BodyHash(respBody) {
				return nil, fmt.Errorf("receipt response hash does not match the bytes received")
			}
			sawResponse = true
		case "upstream.verified":
			if ev["required"] != true {
				return nil, fmt.Errorf("upstream verification was not required for this request")
			}
			if ev["result"] != "verified" {
				upstreamFailure = fmt.Sprintf("upstream verification %v: %v", ev["result"], ev["reason"])
				continue
			}
			sid, _ := ev["session_id"].(string)
			if sid == "" {
				return nil, fmt.Errorf("verified upstream event has no session_id")
			}
			res.SessionID = sid
			verifiedUpstream = true
		}
	}
	if !sawRequest || !sawResponse {
		return nil, fmt.Errorf("receipt is missing request.received or response.returned")
	}
	if id.Serving != "direct" && !verifiedUpstream {
		return nil, fmt.Errorf("%v", upstreamFailure)
	}
	return res, nil
}

func receiptKey(id *Identity, keyID string) (ed25519.PublicKey, error) {
	for _, k := range id.Keyset.ReceiptSigningKeys {
		if k.KeyID != keyID {
			continue
		}
		if k.Algo != "ed25519" {
			return nil, fmt.Errorf("receipt key %q uses unsupported algo %q", keyID, k.Algo)
		}
		b, err := hex.DecodeString(k.PublicKey)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("malformed receipt key %q", keyID)
		}
		return ed25519.PublicKey(b), nil
	}
	return nil, fmt.Errorf("receipt key %q is not in the established keyset", keyID)
}
