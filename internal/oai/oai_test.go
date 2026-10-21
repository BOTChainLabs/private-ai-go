package oai

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/BOTChainLabs/private-ai-go/core"
)

func TestBody(t *testing.T) {
	req := core.InferRequest{Model: "m", Messages: []core.Message{{Role: "user", Content: "hi"}},
		Params: map[string]any{"temperature": 0.2, "model": "other", "stream_options": map[string]any{"x": 1}}}

	b := Body(req, false)
	if b["model"] != "m" || b["stream"] != false || b["temperature"] != 0.2 {
		t.Fatalf("non-stream body %v", b)
	}
	if _, ok := b["stream_options"]; ok {
		t.Fatal("stream_options kept on a non-stream request")
	}
	if b := Body(req, true); b["stream"] != true || b["stream_options"].(map[string]any)["x"] != 1 {
		t.Fatalf("caller stream_options not kept: %v", b)
	}
	req.Params = nil
	if b := Body(req, true); b["stream_options"].(map[string]any)["include_usage"] != true {
		t.Fatalf("usage not requested: %v", b)
	}
}

func TestParseLine(t *testing.T) {
	for _, line := range []string{": keep-alive\n", "\n", "event: ping\n", "data:\n", "retry: 1000\r\n", ""} {
		if _, terminal, ok := parseLine([]byte(line)); ok || terminal {
			t.Errorf("line %q: ok=%v terminal=%v", line, ok, terminal)
		}
	}
	if _, terminal, _ := parseLine([]byte("data: [DONE]\r\n")); !terminal {
		t.Error("[DONE] with CRLF not terminal")
	}
	if data, _, ok := parseLine([]byte(`data:{"a":1}`)); !ok || string(data) != `{"a":1}` {
		t.Errorf("compact data line: %q %v", data, ok)
	}
}

func TestReader(t *testing.T) {
	src := "data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n" +
		": keep-alive\n\n" +
		"data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}\n\n" +
		"data: {\"id\":\"c1\",\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n" +
		"data: {\"id\":\"c1\",\"choices\":[],\"usage\":{\"total_tokens\":5}}\n\n" +
		"data: [DONE]\n\ntrailing-padding"
	tracked := &countingReader{r: strings.NewReader(src)}
	r := NewReader(tracked)
	var sb strings.Builder
	for {
		c, err := r.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		sb.WriteString(c.Content)
	}
	if sb.String() != "hello" || r.ID != "c1" || r.Usage.TotalTokens != 5 || !r.Done() {
		t.Fatalf("content %q id %q usage %+v done %v", sb.String(), r.ID, r.Usage, r.Done())
	}
	if tracked.n != len(src) {
		t.Fatalf("read %d of %d bytes; bytes after [DONE] must be drained", tracked.n, len(src))
	}
	if _, err := r.Next(); err != io.EOF {
		t.Fatalf("Next after EOF: %v", err)
	}
}

func TestReaderErrorEventIsSticky(t *testing.T) {
	r := NewReader(strings.NewReader("data: {\"error\":{\"message\":\"boom\",\"type\":\"server_error\"}}\n\n"))
	_, err := r.Next()
	var e *core.Error
	if !errors.As(err, &e) || e.Code != core.CodeProviderError {
		t.Fatalf("err = %v", err)
	}
	if _, err2 := r.Next(); err2 != err || r.Done() {
		t.Fatalf("error not sticky: %v", err2)
	}
}

// failingReader returns a final line without a newline together with an
// error, once, and then io.EOF, as NEAR's SDK does when it cannot register
// a finished stream. The stream must fail, not look complete.
type failingReader struct{ sent bool }

func (f *failingReader) Read(p []byte) (int, error) {
	if f.sent {
		return 0, io.EOF
	}
	f.sent = true
	n := copy(p, `data: {"id":"c1","choices":[{"delta":{"content":"late"}}]}`)
	return n, errors.New("register failed")
}

func TestReaderTransportErrorIsFatal(t *testing.T) {
	r := NewReader(&failingReader{})
	for {
		c, err := r.Next()
		if err == nil {
			if c.Content == "late" {
				t.Fatal("returned a line that arrived with a transport error")
			}
			continue
		}
		if errors.Is(err, io.EOF) || r.Done() {
			t.Fatalf("stream looked complete after a transport error: %v", err)
		}
		return
	}
}

type countingReader struct {
	r io.Reader
	n int
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}
