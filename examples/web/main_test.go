package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	privateai "github.com/BOTChainLabs/private-ai-go"
)

func newTestServer(t *testing.T) http.Handler {
	t.Helper()
	client, err := privateai.New(privateai.Config{
		Providers: map[privateai.ProviderID]privateai.ProviderConfig{privateai.Phala: {APIKey: "k"}},
		Models:    []privateai.ModelEntry{{Provider: privateai.Phala, Model: "z-ai/glm-5.3"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return withHeaders((&server{client: client}).routes())
}

func do(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
	return w
}

func TestModelsListsChecks(t *testing.T) {
	w := do(newTestServer(t), "GET", "/api/models", "")
	var got []struct {
		Provider string   `json:"provider"`
		Label    string   `json:"label"`
		Streams  bool     `json:"streams"`
		Checks   []string `json:"checks"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || len(got) != 1 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if got[0].Label != "Phala" || !got[0].Streams || len(got[0].Checks) != len(providers[privateai.Phala].Checks) {
		t.Fatalf("%+v", got[0])
	}
}

// Requests the SDK or the page refuses never reach a provider.
func TestChatRejectsBadRequests(t *testing.T) {
	h := newTestServer(t)
	cases := map[string]string{
		"bad JSON":     `{`,
		"no messages":  `{"provider":"phala","model":"z-ai/glm-5.3","messages":[]}`,
		"unknown role": `{"provider":"phala","model":"z-ai/glm-5.3","messages":[{"role":"tool","content":"x"}]}`,
		"other model":  `{"provider":"phala","model":"openai/gpt-5","messages":[{"role":"user","content":"x"}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			w := do(h, "POST", "/api/chat", body)
			var res struct {
				Error struct{ Code, Reason string }
			}
			json.Unmarshal(w.Body.Bytes(), &res)
			if w.Code != http.StatusBadRequest || res.Error.Code == "" || res.Error.Reason == "" {
				t.Fatalf("%d %s", w.Code, w.Body)
			}
		})
	}
}

func TestPageAndHeaders(t *testing.T) {
	w := do(newTestServer(t), "GET", "/", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "Private AI") {
		t.Fatalf("%d", w.Code)
	}
	if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers %v", w.Header())
	}
}

func TestPassword(t *testing.T) {
	h := withPassword("s3cret", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no password: %d", w.Code)
	}
	r.SetBasicAuth("any", "s3cret")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("password: %d", w.Code)
	}
}

func TestIsLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8080": true, "localhost:8080": true, "[::1]:8080": true,
		"0.0.0.0:8080": false, ":8080": false, "10.0.0.5:8080": false, "bad": false,
	} {
		if isLoopback(addr) != want {
			t.Errorf("isLoopback(%q) = %v", addr, !want)
		}
	}
}

// Checks are claimed only for a Verified result, and show its evidence.
func TestVerificationView(t *testing.T) {
	v := &privateai.Verification{Status: privateai.Verified, Provider: privateai.Phala,
		Evidence: privateai.Evidence{TCBStatus: "UpToDate", ReceiptID: "rcpt-1", Receipt: []byte(`{"a":1}`)}}
	out := verificationView(v)
	checks := out["checks"].([]map[string]string)
	if len(checks) != len(providers[privateai.Phala].Checks) || !strings.Contains(checks[0]["detail"], "UpToDate") {
		t.Fatalf("checks %v", checks)
	}
	if string(out["receipt"].(json.RawMessage)) != `{"a":1}` {
		t.Fatalf("receipt %v", out["receipt"])
	}
	v.Status = privateai.Failed
	if _, ok := verificationView(v)["checks"]; ok {
		t.Fatal("checks listed for a failed verification")
	}
}
