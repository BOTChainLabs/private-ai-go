package phala

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BOTChainLabs/private-ai-go/core"
	"github.com/BOTChainLabs/private-ai-go/internal/e2ee"
	"github.com/BOTChainLabs/private-ai-go/internal/oai"
)

// TestGatewayInterop runs E2EE v2 against the real Private AI Gateway: the
// client encrypts, the Rust gateway decrypts, forwards to a mock upstream
// served by this test, encrypts the answer and signs a receipt. The receipt
// must cover the request exactly as the client predicted it.
//
// The gateway runs on dstack's simulator in direct mode, so its own
// attestation is not checked here, only E2EE and receipts. See
// tools/gatewaycheck:
//
//	PRIVATEAI_GATEWAY_INTEROP=http://127.0.0.1:18086 go test ./provider/phala -run GatewayInterop -v
func TestGatewayInterop(t *testing.T) {
	gw := os.Getenv("PRIVATEAI_GATEWAY_INTEROP")
	if gw == "" {
		t.Skip("set PRIVATEAI_GATEWAY_INTEROP to a gateway started with tools/gatewaycheck")
	}
	up := startMockUpstream(t, envOr("PRIVATEAI_GATEWAY_MOCK_ADDR", "0.0.0.0:18087"))
	id, key := interopIdentity(t, gw)

	params := map[string]any{"temperature": 0.7, "top_p": 1e-7, "max_tokens": 64, "seed": int64(1) << 60, "response_format": map[string]any{"type": "text"}}
	msgs := []core.Message{
		{Role: "system", Content: "Answer briefly. <tags> & \"quotes\"   \x01 日本語 😀"},
		{Role: "user", Content: " [1, 2] reads as JSON"},
		{Role: "user", Content: ""},
		{Role: "user", Content: strings.Repeat("long ", 2000)},
	}
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%v", stream), func(t *testing.T) {
			body, _ := json.Marshal(oai.Body(core.InferRequest{Model: "mock-model", Messages: msgs, Params: params}, stream))
			enc, err := e2ee.New(key, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			wire, hashed, err := enc.SealChat(body)
			if err != nil {
				t.Fatal(err)
			}
			req, _ := http.NewRequest(http.MethodPost, gw+"/v1/chat/completions", bytes.NewReader(wire))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept-Encoding", "identity")
			enc.SetHeaders(req.Header)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			respBody, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || resp.Header.Get("X-E2EE-Applied") != "true" {
				t.Fatalf("HTTP %d, applied %q: %s", resp.StatusCode, resp.Header.Get("X-E2EE-Applied"), respBody)
			}

			// The gateway forwarded the decrypted messages; array-like content
			// as one text part.
			got := up.last()
			for i, m := range msgs {
				var want any = m.Content
				if i == 1 {
					want = []any{map[string]any{"type": "text", "text": m.Content}}
				}
				var fwd any
				if json.Unmarshal([]byte(got[i]), &fwd); !reflect.DeepEqual(fwd, want) {
					t.Errorf("message %d forwarded as %.80s", i, got[i])
				}
			}

			// The receipt covers the restored request and the encrypted answer.
			rid := resp.Header.Get("X-Receipt-Id")
			raw := fetch(t, gw+"/v1/aci/receipts/"+rid)
			rr, err := VerifyReceipt(raw, id, hashed, respBody)
			if err != nil {
				t.Fatalf("receipt: %v\nreceipt %s", err, raw)
			}
			// The SDK requires the signed receipt_id to be the one named.
			if rr.ReceiptID != rid {
				t.Fatalf("X-Receipt-Id %q, receipt_id %q", rid, rr.ReceiptID)
			}
			// Reached without a pinned TLS key, the same direct gateway's
			// receipt is refused: its serving mode is then not trusted, and the
			// receipt records no upstream TEE session.
			unpinned := *id
			unpinned.TLSPins = nil
			if _, err := VerifyReceipt(raw, &unpinned, hashed, respBody); err == nil {
				t.Fatal("a direct gateway's receipt was accepted without a pinned TLS key")
			}

			// And the answer decrypts.
			var content strings.Builder
			if stream {
				rd := oai.NewReader(bytes.NewReader(respBody))
				rd.Open = enc.OpenChatEvent
				for {
					c, err := rd.Next()
					if errors.Is(err, io.EOF) {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					content.WriteString(c.Content)
				}
			} else {
				plain, err := enc.OpenChat(respBody)
				if err != nil {
					t.Fatal(err)
				}
				c, _ := oai.ParseCompletion(plain)
				content.WriteString(c.Content)
				if !bytes.Contains(plain, []byte(`"reasoning_content":"thinking"`)) {
					t.Errorf("reasoning not decrypted: %s", plain)
				}
			}
			if content.String() != mockAnswer {
				t.Fatalf("decrypted %q", content.String())
			}
			if bytes.Contains(respBody, []byte("secret")) {
				t.Fatal("answer travelled in plaintext")
			}

			// The same request again is a replay.
			req2, _ := http.NewRequest(http.MethodPost, gw+"/v1/chat/completions", bytes.NewReader(wire))
			req2.Header = req.Header.Clone()
			resp2, err := http.DefaultClient.Do(req2)
			if err != nil {
				t.Fatal(err)
			}
			b2, _ := io.ReadAll(resp2.Body)
			resp2.Body.Close()
			if resp2.StatusCode != http.StatusBadRequest || !bytes.Contains(b2, []byte("e2ee_replay_detected")) {
				t.Fatalf("replay: HTTP %d %s", resp2.StatusCode, b2)
			}
		})
	}
}

const mockAnswer = "the secret answer,   with <markup> & 😀"

type mockUpstream struct {
	mu       sync.Mutex
	messages []string // contents of the last request, as JSON
}

func (m *mockUpstream) last() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.messages
}

func startMockUpstream(t *testing.T, addr string) *mockUpstream {
	t.Helper()
	m := &mockUpstream{}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Stream   bool `json:"stream"`
			Messages []struct {
				Content json.RawMessage `json:"content"`
			} `json:"messages"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		var contents []string
		for _, msg := range req.Messages {
			contents = append(contents, string(msg.Content))
		}
		m.mu.Lock()
		m.messages = contents
		m.mu.Unlock()
		if !req.Stream {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":"chatcmpl-mock","object":"chat.completion","model":"mock-model","choices":[{"index":0,"message":{"role":"assistant","content":%s,"reasoning_content":"thinking"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":7,"total_tokens":12}}`, mustJSON(mockAnswer))
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		half := len(string([]rune(mockAnswer)[:10]))
		for _, ev := range []string{
			`{"id":"chatcmpl-mock","object":"chat.completion.chunk","model":"mock-model","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}`,
			`{"id":"chatcmpl-mock","object":"chat.completion.chunk","model":"mock-model","choices":[{"index":0,"delta":{"reasoning_content":"thinking"}}]}`,
			fmt.Sprintf(`{"id":"chatcmpl-mock","object":"chat.completion.chunk","model":"mock-model","choices":[{"index":0,"delta":{"content":%s}}]}`, mustJSON(mockAnswer[:half])),
			fmt.Sprintf(`{"id":"chatcmpl-mock","object":"chat.completion.chunk","model":"mock-model","choices":[{"index":0,"delta":{"content":%s},"finish_reason":"stop"}]}`, mustJSON(mockAnswer[half:])),
			`{"id":"chatcmpl-mock","object":"chat.completion.chunk","model":"mock-model","choices":[],"usage":{"prompt_tokens":5,"completion_tokens":7,"total_tokens":12}}`,
		} {
			fmt.Fprintf(w, "data: %s\n\n", ev)
			w.(http.Flusher).Flush()
		}
		fmt.Fprint(w, "data: [DONE]\n\n")
	})}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return m
}

// interopIdentity reads the gateway's keyset without checking its quote:
// the simulator's quote is not genuine.
func interopIdentity(t *testing.T, gw string) (*Identity, string) {
	t.Helper()
	var rep Report
	if err := json.Unmarshal(fetch(t, gw+"/v1/aci/attestation?nonce="+strings.Repeat("00", 32)), &rep); err != nil {
		t.Fatal(err)
	}
	keysetJSON, digest, err := canonicalKeyset(rep.Attestation.WorkloadKeyset)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := parseKeyset(keysetJSON)
	if err != nil {
		t.Fatal(err)
	}
	var key string
	for _, raw := range ks.E2EEPublicKeys {
		var k KeyEntry
		if json.Unmarshal(raw, &k) == nil && k.Algo == e2ee.Algo {
			key = k.PublicKey
		}
	}
	if key == "" {
		t.Fatal("gateway publishes no X25519 key")
	}
	// The report came over plain HTTP from the simulator; in production a
	// direct gateway's report arrives over a TLS key its keyset lists, which
	// is what lets VerifyReceipt trust its serving mode. That channel is not
	// what this test checks (provider_test.go does), so the identity is taken
	// as reached over a pinned key.
	return &Identity{KeysetDigest: digest, Keyset: ks, Serving: rep.ServiceCapabilities.Serving,
		TLSPins: []string{"interop: the report's channel is not part of this test"}}, key
}

func fetch(t *testing.T, u string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: HTTP %d %s", u, resp.StatusCode, b)
	}
	return b
}

func mustJSON(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return strings.TrimSuffix(b.String(), "\n")
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
