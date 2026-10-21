package phala

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/BOTChainLabs/private-ai-go/core"
	"github.com/BOTChainLabs/private-ai-go/internal/oai"
)

// route names how a Phala result was served: through the attested ACI
// gateway, to a verified TEE upstream.
const route = "phala-aci"

// exchange is one request sent over an attested session. reqBody holds the
// exact bytes sent, which the receipt's request hash must match.
type exchange struct {
	s       *session
	reqBody []byte
	resp    *http.Response
}

// send serializes the request once, sends it over the session's pinned
// client and checks the status. On success the caller owns resp.Body.
func (p *Provider) send(ctx context.Context, req core.InferRequest, stream bool) (*exchange, error) {
	s, err := p.session(ctx)
	if err != nil {
		return nil, err
	}
	reqBody, err := buildBody(req, stream)
	if err != nil {
		return nil, core.Errorf(core.CodeInvalidRequest, err, "encode request")
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base.JoinPath("/v1/chat/completions").String(), bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Authorization", "Bearer "+p.apiKey)
	hreq.Header.Set("Content-Type", "application/json")
	// The receipt hashes the wire bytes, so they must not be re-encoded.
	hreq.Header.Set("Accept-Encoding", "identity")
	if stream {
		hreq.Header.Set("Accept", "text/event-stream")
	}

	client := s.client
	if stream {
		client = s.streamClient
	}
	resp, err := client.Do(hreq)
	if err != nil {
		if errors.Is(err, ErrTLSPinMismatch) {
			p.invalidate()
			return nil, core.Errorf(core.CodeTLSPinMismatch, err, "inference request")
		}
		return nil, core.Wrap(ctx, core.CodeProviderError, err, "inference request")
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		code := core.CodeProviderError
		if resp.StatusCode == http.StatusServiceUnavailable && bytes.Contains(body, []byte("upstream_verification_failed")) {
			code = core.CodeRouteNotTEE
		}
		return nil, core.Errorf(code, nil, "HTTP %d: %s", resp.StatusCode, truncate(body, 300))
	}
	// Headers are unauthenticated hints, but a changed keyset means the
	// identity must be re-established before anything else is sent (§5.2).
	if d := resp.Header.Get("X-ACI-Keyset-Digest"); d != "" && d != s.id.KeysetDigest {
		p.invalidate()
	}
	return &exchange{s: s, reqBody: reqBody, resp: resp}, nil
}

// verify fetches the receipt for a completed exchange and checks it against
// the exact response bytes. It returns a Verified result or a *core.Error
// carrying the verification details.
func (p *Provider) verify(ctx context.Context, ex *exchange, receiptID, model string, respBody []byte) (core.Verification, error) {
	ver := core.Verification{Status: core.Unverified, Provider: core.Phala, Model: model, Route: route}
	fail := func(status core.Status, code string, err error) (core.Verification, error) {
		ver.Status = status
		ver.Reasons = []string{err.Error()}
		v := ver
		return ver, &core.Error{Code: code, Message: "verify response", Verification: &v, Cause: err}
	}

	if receiptID == "" {
		return fail(core.Unverified, core.CodeEvidenceUnavailable, errors.New("response carries no receipt id"))
	}
	ver.Evidence.ReceiptID = receiptID
	rawReceipt, err := p.fetchReceipt(ctx, ex.s.client, receiptID)
	if err != nil && ctx.Err() != nil {
		return ver, err // the caller gave up
	}
	if err != nil {
		return fail(core.Unverified, core.CodeEvidenceUnavailable, err)
	}
	ver.Evidence.Receipt = rawReceipt

	// Verify under the keyset the receipt itself names (it is signed), not
	// the response header.
	var named struct {
		Digest string `json:"workload_keyset_digest"`
	}
	if err := json.Unmarshal(rawReceipt, &named); err != nil || named.Digest == "" {
		return fail(core.Failed, core.CodeReceiptInvalid, fmt.Errorf("receipt does not name a keyset: %v", err))
	}
	vs := ex.s
	if named.Digest != vs.id.KeysetDigest {
		if vs, err = p.sessionFor(ctx, named.Digest); err != nil {
			return fail(core.Unverified, core.CodeEvidenceUnavailable, err)
		}
	}
	ver.Evidence.KeysetDigest = vs.id.KeysetDigest
	ver.Evidence.Keyset = vs.id.KeysetJSON
	ver.Evidence.AppID = vs.id.AppID
	ver.Evidence.OSImageHash = vs.id.OSImageHash
	ver.Evidence.ComposeHash = vs.id.ComposeHash
	ver.Evidence.TCBStatus = vs.id.TCBStatus
	if !p.now().Before(vs.id.NotAfter) {
		return fail(core.Unverified, core.CodeEvidenceUnavailable, errors.New("keyset expired before the receipt was verified"))
	}

	rr, err := VerifyReceipt(rawReceipt, vs.id, ex.reqBody, respBody)
	if err != nil {
		return fail(core.Failed, core.CodeReceiptInvalid, err)
	}
	ver.Status = core.Verified
	ver.Evidence.SessionID = rr.SessionID
	return ver, nil
}

// Infer sends one non-streaming chat completion and returns it only when its
// receipt verifies against an attested identity.
func (p *Provider) Infer(ctx context.Context, req core.InferRequest) (*core.InferResult, error) {
	ex, err := p.send(ctx, req, false)
	if err != nil {
		return nil, err
	}
	defer ex.resp.Body.Close()
	respBody, err := readLimited(ex.resp.Body)
	if err != nil {
		return nil, core.Wrap(ctx, core.CodeProviderError, err, "read inference response")
	}

	ver, err := p.verify(ctx, ex, ex.resp.Header.Get("X-Receipt-Id"), req.Model, respBody)
	if err != nil {
		return nil, err
	}
	c, err := oai.ParseCompletion(respBody)
	if err != nil {
		return nil, err
	}
	return &core.InferResult{Content: c.Content, Raw: respBody, Usage: c.Usage, Verification: ver}, nil
}

// fetchReceipt retries briefly: the receipt is finalized when the response
// completes, so a short race with the lookup is possible.
func (p *Provider) fetchReceipt(ctx context.Context, client *http.Client, id string) (json.RawMessage, error) {
	u := p.base.JoinPath("/v1/aci/receipts", id).String()
	var last error
	for attempt := range 3 {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt) * 300 * time.Millisecond):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+p.apiKey)
		req.Header.Set("Accept-Encoding", "identity")
		resp, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := readLimited(resp.Body)
		resp.Body.Close()
		switch {
		case err != nil:
			last = err
		case resp.StatusCode == http.StatusOK:
			return body, nil
		case resp.StatusCode == http.StatusNotFound:
			last = fmt.Errorf("receipt %s not found", id)
		default:
			return nil, fmt.Errorf("receipt %s: HTTP %d", id, resp.StatusCode)
		}
	}
	return nil, last
}

// buildBody serializes the request once. aci_verified makes the gateway
// refuse rather than serve through an unattested upstream (§5.3); it
// replaces any provider field the caller set.
func buildBody(req core.InferRequest, stream bool) ([]byte, error) {
	body := oai.Body(req, stream)
	body["provider"] = map[string]any{"aci_verified": true}
	return json.Marshal(body)
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}
