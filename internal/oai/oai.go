// Package oai is the OpenAI-compatible wire format shared by the providers:
// request bodies, completions and server-sent event streams.
package oai

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"

	"github.com/BOTChainLabs/private-ai-go/core"
)

// Body builds a chat completion request. The SDK owns model, messages and
// stream; caller Params are copied as is. Streams ask for usage in the final
// event unless the caller set stream_options.
func Body(req core.InferRequest, stream bool) map[string]any {
	body := make(map[string]any, len(req.Params)+4)
	maps.Copy(body, req.Params)
	body["model"] = req.Model
	body["messages"] = req.Messages
	body["stream"] = stream
	if stream {
		if _, ok := body["stream_options"]; !ok {
			body["stream_options"] = map[string]any{"include_usage": true}
		}
	} else {
		delete(body, "stream_options")
	}
	return body
}

// Completion is the part of a non-streaming response the SDK uses.
type Completion struct {
	ID      string
	Content string
	Usage   core.Usage
}

func ParseCompletion(body []byte) (Completion, error) {
	var c struct {
		ID      string `json:"id"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage core.Usage `json:"usage"`
	}
	if err := json.Unmarshal(body, &c); err != nil {
		return Completion{}, core.Errorf(core.CodeProviderError, err, "parse completion")
	}
	out := Completion{ID: c.ID, Usage: c.Usage}
	if len(c.Choices) > 0 {
		out.Content = c.Choices[0].Message.Content
	}
	return out, nil
}

// Reader reads an OpenAI-style SSE stream. It is not safe for concurrent use.
type Reader struct {
	r *bufio.Reader
	// ID is the completion id carried by the events.
	ID string
	// Usage is set by the final usage event, when the server sends one.
	Usage core.Usage

	done bool
	err  error
}

func NewReader(r io.Reader) *Reader { return &Reader{r: bufio.NewReader(r)} }

// Next returns the next data event, or io.EOF once the stream is complete.
// After [DONE] it reads the body to its end, so a caller hashing the bytes
// sees exactly what the server sent. Errors are sticky.
func (r *Reader) Next() (core.Chunk, error) {
	if r.err != nil {
		return core.Chunk{}, r.err
	}
	if r.done {
		return core.Chunk{}, io.EOF
	}
	for {
		line, err := r.r.ReadBytes('\n')
		// A transport error ends the stream even if a partial line came with
		// it: bufio reports an error only once, so continuing would let a
		// failed stream look complete.
		if err != nil && !errors.Is(err, io.EOF) {
			return r.fail(err)
		}
		data, terminal, ok := parseLine(line)
		switch {
		case terminal:
			if _, err := io.Copy(io.Discard, r.r); err != nil {
				return r.fail(err)
			}
			r.done = true
			return core.Chunk{}, io.EOF
		case ok:
			chunk, perr := r.event(data)
			if perr != nil {
				return r.fail(perr)
			}
			return chunk, nil
		}
		if errors.Is(err, io.EOF) {
			r.done = true
			return core.Chunk{}, io.EOF
		}
	}
}

// Done reports whether the stream was read to its end without error.
func (r *Reader) Done() bool { return r.done }

// Err is the error that stopped the stream, if any.
func (r *Reader) Err() error { return r.err }

// Fail stops the stream with err, for failures found by the caller (for
// example a size limit). Later calls to Next return err.
func (r *Reader) Fail(err error) {
	r.err = err
	r.done = false
}

func (r *Reader) fail(err error) (core.Chunk, error) {
	r.Fail(err)
	return core.Chunk{}, err
}

func (r *Reader) event(data []byte) (core.Chunk, error) {
	var ev struct {
		ID      string `json:"id"`
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
		Usage *core.Usage `json:"usage"`
		Error *struct {
			Message string `json:"message"`
			Type    string `json:"type"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &ev); err != nil {
		return core.Chunk{}, core.Errorf(core.CodeProviderError, err, "parse stream event")
	}
	if ev.Error != nil {
		return core.Chunk{}, core.Errorf(core.CodeProviderError, nil, "stream error %s: %s", ev.Error.Type, ev.Error.Message)
	}
	if ev.ID != "" {
		r.ID = ev.ID
	}
	if ev.Usage != nil {
		r.Usage = *ev.Usage
	}
	chunk := core.Chunk{Raw: append(json.RawMessage(nil), data...)}
	if len(ev.Choices) > 0 {
		chunk.Content = ev.Choices[0].Delta.Content
	}
	return chunk, nil
}

// parseLine handles one SSE line. Only data lines carry events; comments,
// other fields and blank separators are skipped.
func parseLine(line []byte) (data []byte, terminal, ok bool) {
	data, found := bytes.CutPrefix(bytes.TrimRight(line, "\r\n"), []byte("data:"))
	if !found {
		return nil, false, false
	}
	data = bytes.TrimSpace(data)
	switch {
	case bytes.Equal(data, []byte("[DONE]")):
		return nil, true, false
	case len(data) == 0:
		return nil, false, false
	}
	return data, false, true
}
