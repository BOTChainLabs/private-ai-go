package phala

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/BOTChainLabs/private-ai-go/core"
	"github.com/BOTChainLabs/private-ai-go/internal/oai"
)

// stream reads an SSE chat completion while keeping every byte received:
// the receipt hashes "the raw in-order stream including framing" (§7.4), so
// verification needs the wire bytes, not the parsed events.
type stream struct {
	ctx    context.Context // the caller's context
	cancel func()          // ends the request's context
	p      *Provider
	ex     *exchange
	model  string

	raw bytes.Buffer // exact bytes received so far
	rd  *oai.Reader

	closeOnce sync.Once
	verified  *core.Verification
}

// Stream sends a streaming chat completion. The returned content is not
// trustworthy until the stream is read to io.EOF and Verify succeeds.
//
// Options.Timeout bounds opening the stream, until the response headers
// arrive, and Verify. Reading the stream is bounded by ctx alone, since an
// answer can take long to generate.
func (p *Provider) Stream(ctx context.Context, req core.InferRequest) (core.ProviderStream, error) {
	// The request's context must outlive the opening, so the timeout cancels
	// it only while the stream is opening.
	rctx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(p.timeout, cancel)
	ex, err := p.send(rctx, ctx, req, true)
	if fired := !timer.Stop(); fired && ctx.Err() == nil {
		if err == nil {
			ex.resp.Body.Close()
		}
		cancel()
		code := core.CodeProviderError
		var ce *core.Error
		if errors.As(err, &ce) {
			code = ce.Code
		}
		return nil, core.Errorf(code, err, "the stream did not open within %s", p.timeout)
	}
	if err != nil {
		cancel()
		return nil, err
	}
	st := &stream{ctx: ctx, cancel: cancel, p: p, ex: ex, model: req.Model}
	st.rd = oai.NewReader(io.TeeReader(io.LimitReader(ex.resp.Body, maxBodyBytes+1), &st.raw))
	if ex.enc != nil {
		// raw keeps the encrypted wire bytes, which the receipt covers.
		st.rd.Open = ex.enc.OpenChatEvent
	}
	return st, nil
}

func (st *stream) Recv() (core.Chunk, error) {
	chunk, err := st.rd.Next()
	if err == nil && st.raw.Len() > maxBodyBytes {
		err = fmt.Errorf("stream exceeds %d bytes", maxBodyBytes)
	}
	switch {
	case err == nil:
		return chunk, nil
	case errors.Is(err, io.EOF):
		if st.raw.Len() > maxBodyBytes {
			return core.Chunk{}, st.fail(fmt.Errorf("stream exceeds %d bytes", maxBodyBytes))
		}
		st.Close()
		return core.Chunk{}, io.EOF
	default:
		return core.Chunk{}, st.fail(err)
	}
}

// fail records a read failure; the stream can no longer be verified.
func (st *stream) fail(err error) error {
	var ce *core.Error
	if !errors.As(err, &ce) {
		err = core.Wrap(st.ctx, core.CodeProviderError, err, "read stream")
	}
	st.rd.Fail(err)
	st.Close()
	return err
}

// Verify checks the receipt against the complete stream. A stream that was
// not read to the end, or that failed while reading, cannot be verified.
func (st *stream) Verify(ctx context.Context) (*core.Verification, error) {
	if st.verified != nil {
		v := *st.verified
		return &v, nil
	}
	if !st.rd.Done() {
		return nil, core.StreamUnfinished(st.p.id, st.model, st.p.route, st.rd.Err())
	}
	// With aci_verified the gateway never commits a stream early, so the
	// header is expected; the completion id is the spec's fallback (§5.2).
	receiptID := st.ex.resp.Header.Get("X-Receipt-Id")
	if receiptID == "" {
		receiptID = st.rd.ID
	}
	vctx, cancel := context.WithTimeout(ctx, st.p.timeout)
	defer cancel()
	ver, err := st.p.verify(vctx, ctx, st.ex, receiptID, st.model, st.raw.Bytes())
	if err != nil {
		return nil, err
	}
	st.verified = &ver
	v := ver
	return &v, nil
}

func (st *stream) Usage() core.Usage { return st.rd.Usage }

func (st *stream) Close() error {
	var err error
	st.closeOnce.Do(func() {
		err = st.ex.resp.Body.Close()
		st.cancel()
	})
	return err
}
