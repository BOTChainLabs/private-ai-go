package phala

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BOTChainLabs/private-ai-go/core"
)

// TestLiveInference calls inference.phala.com for real: preflight, a plain
// and a streamed completion, each verified against its signed receipt, and
// a model outside the TEE catalog, which must be refused.
//
//	PHALA_API_KEY=... go test ./provider/phala -run LiveInference -v
func TestLiveInference(t *testing.T) {
	key := os.Getenv("PHALA_API_KEY")
	if key == "" {
		t.Skip("set PHALA_API_KEY to run against inference.phala.com")
	}
	model := os.Getenv("PHALA_MODEL")
	if model == "" {
		model = "z-ai/glm-5.3"
	}
	p, err := New(Options{APIKey: key})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	req := core.InferRequest{Provider: core.Phala, Model: model, Messages: []core.Message{{Role: "user", Content: "Reply with one short sentence."}}}

	t.Run("infer", func(t *testing.T) {
		res, err := p.Infer(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		ev := res.Verification.Evidence
		if res.Verification.Status != core.Verified || ev.SessionID == "" || len(ev.Receipt) == 0 || res.Usage.TotalTokens == 0 {
			t.Fatalf("result %+v", res)
		}
		t.Logf("%q", res.Content)
		t.Logf("receipt %s, upstream session %s, compose %s, TCB %s", ev.ReceiptID, ev.SessionID, ev.ComposeHash, ev.TCBStatus)
		saveForCrossCheck(t, req, res)
	})

	t.Run("stream", func(t *testing.T) {
		st, err := p.Stream(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		var sb strings.Builder
		for {
			c, err := st.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			sb.WriteString(c.Content)
		}
		v, err := st.Verify(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if v.Status != core.Verified || st.Usage().TotalTokens == 0 {
			t.Fatalf("verification %+v, usage %+v", v, st.Usage())
		}
		t.Logf("%q (receipt %s)", sb.String(), v.Evidence.ReceiptID)
	})

	t.Run("non-TEE model refused", func(t *testing.T) {
		// openai/gpt-5 is served only by Phala's non-TEE route.
		res, err := p.Infer(ctx, core.InferRequest{Provider: core.Phala, Model: "openai/gpt-5", Messages: req.Messages})
		if err == nil || res != nil {
			t.Fatalf("a non-TEE model returned a result: %+v", res)
		}
		t.Logf("refused as expected: %v", err)
	})
}

// saveForCrossCheck writes a real receipt and the exact bytes it covers to
// PRIVATEAI_CROSSCHECK_DIR, so tools/crosscheck can have Phala's official
// verifier check a production receipt too.
func saveForCrossCheck(t *testing.T, req core.InferRequest, res *core.InferResult) {
	dir := os.Getenv("PRIVATEAI_CROSSCHECK_DIR")
	if dir == "" {
		return
	}
	reqBody, err := buildBody(req, false) // deterministic: the bytes that were sent
	if err != nil {
		t.Fatal(err)
	}
	ev := res.Verification.Evidence
	out, _ := json.MarshalIndent(map[string]any{
		"receipt":     string(ev.Receipt),
		"request":     string(reqBody),
		"response":    string(res.Raw),
		"keyset":      ev.Keyset,
		"established": ev.KeysetDigest,
	}, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "live-receipt.json"), out, 0o600); err != nil {
		t.Fatal(err)
	}
}
