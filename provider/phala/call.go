package phala

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/BOTChainLabs/private-ai-go/core"
	"github.com/BOTChainLabs/private-ai-go/internal/e2ee"
	"github.com/BOTChainLabs/private-ai-go/internal/oai"
)

// exchange is one request sent over an attested session. hashed holds the
// request bytes the receipt's request hash must match: the exact bytes sent,
// or with E2EE the request as the gateway serializes it after decrypting it.
type exchange struct {
	s      *session
	hashed []byte
	enc    *e2ee.Request // nil without E2EE
	resp   *http.Response
}

// send sends the request over an attested session and checks the status. On
// success the caller owns resp.Body. A request the gateway refused because
// its E2EE key had rotated was never processed, so it is sent once more
// under the re-established identity. ctx bounds the call; caller is the
// caller's own context, whose end is reported as is.
func (p *Provider) send(ctx, caller context.Context, req core.InferRequest, stream bool) (*exchange, error) {
	ex, rotated, err := p.sendOnce(ctx, caller, req, stream)
	if rotated {
		ex, _, err = p.sendOnce(ctx, caller, req, stream)
	}
	return ex, err
}

// sendOnce serializes the request, sends it over the session's pinned client
// and checks the status. rotated reports a refusal for a stale E2EE key.
func (p *Provider) sendOnce(ctx, caller context.Context, req core.InferRequest, stream bool) (ex *exchange, rotated bool, err error) {
	s, err := p.session(ctx)
	if err != nil {
		return nil, false, stopped(caller, core.CodeEvidenceUnavailable, err, "attest")
	}
	reqBody, err := buildBody(req, stream)
	if err != nil {
		return nil, false, core.Errorf(core.CodeInvalidRequest, err, "encode request")
	}
	hashed := reqBody
	var enc *e2ee.Request
	if p.e2ee {
		if enc, err = e2ee.New(s.id.E2EEKey, p.now()); err != nil {
			return nil, false, core.Errorf(core.CodeAttestationFailed, err, "attested E2EE key")
		}
		if reqBody, hashed, err = enc.SealChat(reqBody); err != nil {
			return nil, false, core.Errorf(core.CodeInvalidRequest, err, "encrypt request")
		}
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base.JoinPath("/v1/chat/completions").String(), bytes.NewReader(reqBody))
	if err != nil {
		return nil, false, err
	}
	if enc != nil {
		enc.SetHeaders(hreq.Header)
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
			return nil, false, core.Errorf(core.CodeTLSPinMismatch, err, "inference request")
		}
		return nil, false, core.Wrap(caller, core.CodeProviderError, err, "inference request")
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		code := core.CodeProviderError
		if resp.StatusCode == http.StatusServiceUnavailable && bytes.Contains(body, []byte("upstream_verification_failed")) {
			code = core.CodeRouteNotTEE
		}
		// The gateway's E2EE key changed with its keyset: attest again.
		if enc != nil && resp.StatusCode == http.StatusBadRequest && bytes.Contains(body, []byte("e2ee_model_key_mismatch")) {
			p.invalidate()
			rotated = true
		}
		return nil, rotated, core.Errorf(code, nil, "HTTP %d: %s", resp.StatusCode, truncate(body, 300))
	}
	// Headers are unauthenticated hints, but a changed keyset means the
	// identity must be re-established before anything else is sent (§5.2).
	if d := resp.Header.Get("X-ACI-Keyset-Digest"); d != "" && d != s.id.KeysetDigest {
		p.invalidate()
	}
	// The answer would arrive in plaintext; decryption would fail anyway,
	// but this names the cause.
	if enc != nil && resp.Header.Get("X-E2EE-Applied") != "true" {
		resp.Body.Close()
		return nil, false, core.Errorf(core.CodeProviderError, nil, "the gateway did not encrypt its response (E2EE v%s)", e2ee.Version)
	}
	return &exchange{s: s, hashed: hashed, enc: enc, resp: resp}, false, nil
}

// verify fetches the receipt for a completed exchange and checks it against
// the exact response bytes. receiptID is the X-Receipt-Id the gateway named
// or, when byCompletion, the completion id it is looked up by instead. It
// returns a Verified result or a *core.Error carrying the verification
// details. ctx bounds the verification; when the caller's own context ends,
// its error is returned as is.
func (p *Provider) verify(ctx, caller context.Context, ex *exchange, receiptID string, byCompletion bool, model string, respBody []byte) (core.Verification, error) {
	ver := core.Verification{Status: core.Unverified, Provider: p.id, Model: model, Route: p.route}
	if ex.enc != nil {
		ver.Evidence.E2EE = e2ee.Algo
	}
	ver.Evidence.TLSPinned = len(ex.s.id.TLSPins) > 0
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
	if err != nil && caller.Err() != nil {
		return ver, err // the caller gave up
	}
	if err != nil {
		return fail(core.Unverified, core.CodeEvidenceUnavailable, err)
	}
	ver.Evidence.Receipt = rawReceipt

	// Verify under the keyset the receipt itself names (it is signed), not
	// the response header. The keyset the request was sent under was fresh
	// when it was sent, so it stays trusted for this receipt, however long
	// the answer took; any other keyset must have been attested within
	// identityMaxAge (sessionFor).
	var named struct {
		Digest string `json:"workload_keyset_digest"`
	}
	if err := json.Unmarshal(rawReceipt, &named); err != nil || named.Digest == "" {
		return fail(core.Failed, core.CodeReceiptInvalid, fmt.Errorf("receipt does not name a keyset: %v", err))
	}
	vs := ex.s
	if named.Digest != vs.id.KeysetDigest {
		if vs, err = p.sessionFor(ctx, named.Digest); err != nil {
			if caller.Err() != nil {
				return ver, err
			}
			return fail(core.Unverified, core.CodeEvidenceUnavailable, err)
		}
	}
	ver.Evidence.KeysetDigest = vs.id.KeysetDigest
	ver.Evidence.Keyset = vs.id.KeysetJSON
	ver.Evidence.AppID = vs.id.AppID
	ver.Evidence.OSImageHash = vs.id.OSImageHash
	ver.Evidence.ComposeHash = vs.id.ComposeHash
	ver.Evidence.TCBStatus = vs.id.TCBStatus
	ver.Evidence.AdvisoryIDs = slices.Clone(vs.id.AdvisoryIDs)
	if !p.now().Before(vs.id.NotAfter) {
		return fail(core.Unverified, core.CodeEvidenceUnavailable, errors.New("keyset expired before the receipt was verified"))
	}

	rr, err := VerifyReceipt(rawReceipt, vs.id, ex.hashed, respBody)
	if err != nil {
		return fail(core.Failed, core.CodeReceiptInvalid, err)
	}
	// The receipt must be the one asked for, as it states under its
	// signature.
	if byCompletion && rr.ChatID != receiptID && rr.ReceiptID != receiptID {
		return fail(core.Failed, core.CodeReceiptInvalid, fmt.Errorf("receipt %q, returned for completion %q, is for completion %q", rr.ReceiptID, receiptID, rr.ChatID))
	}
	if !byCompletion && rr.ReceiptID != receiptID {
		return fail(core.Failed, core.CodeReceiptInvalid, fmt.Errorf("receipt %q was returned for receipt %q", rr.ReceiptID, receiptID))
	}
	ver.Status = core.Verified
	ver.Evidence.ReceiptID = rr.ReceiptID
	ver.Evidence.SessionID = rr.SessionID
	return ver, nil
}

// Infer sends one non-streaming chat completion and returns it only when its
// receipt verifies against an attested identity. With E2EE, Raw is the
// response with its generated content decrypted. Options.Timeout bounds the
// whole call: the preflight, sending, reading the answer and verifying it.
func (p *Provider) Infer(ctx context.Context, req core.InferRequest) (*core.InferResult, error) {
	callCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	ex, err := p.send(callCtx, ctx, req, false)
	if err != nil {
		return nil, err
	}
	defer ex.resp.Body.Close()
	respBody, err := readLimited(ex.resp.Body)
	if err != nil {
		return nil, core.Wrap(ctx, core.CodeProviderError, err, "read inference response")
	}

	ver, err := p.verify(callCtx, ctx, ex, ex.resp.Header.Get("X-Receipt-Id"), false, req.Model, respBody)
	if err != nil {
		return nil, err
	}
	// The receipt covers the encrypted bytes, so decrypt only what verified.
	if ex.enc != nil {
		if respBody, err = ex.enc.OpenChat(respBody); err != nil {
			return nil, core.Errorf(core.CodeProviderError, err, "decrypt response")
		}
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

// stopped gives an error that ended a step an SDK code. A *core.Error and
// the caller's own cancellation are returned as they are; anything else,
// such as the call's timeout, gets code.
func stopped(caller context.Context, code string, err error, msg string) error {
	var ce *core.Error
	if errors.As(err, &ce) {
		return err
	}
	return core.Wrap(caller, code, err, msg)
}

func truncate(b []byte, n int) string {
	if len(b) > n {
		return string(b[:n]) + "..."
	}
	return string(b)
}
