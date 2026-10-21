package near

import (
	"context"
	"io"

	"github.com/BOTChainLabs/private-ai-go/core"
)

// Stream returns a verified completion through the stream interface, as a
// single chunk. NEAR signs streamed responses with its gateway key only,
// which does not prove the model produced them, so a stream is served by a
// verified non-streaming call instead of being returned unverified.
func (p *Provider) Stream(ctx context.Context, req core.InferRequest) (core.ProviderStream, error) {
	res, err := p.Infer(ctx, req)
	if err != nil {
		return nil, err
	}
	return &bufferedStream{res: res}, nil
}

// bufferedStream replays one verified result as a stream.
type bufferedStream struct {
	res       *core.InferResult
	sent, eof bool
}

func (s *bufferedStream) Recv() (core.Chunk, error) {
	if !s.sent {
		s.sent = true
		return core.Chunk{Content: s.res.Content, Raw: s.res.Raw}, nil
	}
	s.eof = true
	return core.Chunk{}, io.EOF
}

// Verify returns the verification of the underlying call. Like every
// stream, it requires the stream to have been read to the end.
func (s *bufferedStream) Verify(context.Context) (*core.Verification, error) {
	if !s.eof {
		return nil, core.StreamUnfinished(core.NEAR, s.res.Verification.Model, s.res.Verification.Route, nil)
	}
	v := s.res.Verification
	return &v, nil
}

func (s *bufferedStream) Usage() core.Usage { return s.res.Usage }
func (s *bufferedStream) Close() error      { return nil }
