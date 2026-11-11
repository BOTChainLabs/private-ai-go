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
	return handler(client, "", true)
}

// do sends a request as the page itself does: to the address it was opened
// at, and for a POST with JSON from the same origin.
func do(h http.Handler, method, path, body string, header ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "127.0.0.1:8080"
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://127.0.0.1:8080")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
	}
	for i := 0; i+1 < len(header); i += 2 {
		if header[i] == "Host" {
			r.Host = header[i+1]
		} else {
			r.Header.Set(header[i], header[i+1])
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

// Beyond localhost the demo needs both a password and TLS: basic auth over
// plain HTTP would send the password, and the answers, in clear.
func TestListenPolicy(t *testing.T) {
	cases := []struct {
		addr, password, cert, key string
		ok                        bool
	}{
		{"127.0.0.1:8080", "", "", "", true},
		{"localhost:8080", "", "", "", true},
		{"0.0.0.0:8443", "pw", "cert.pem", "key.pem", true},
		{"0.0.0.0:8080", "", "", "", false},
		{"0.0.0.0:8080", "pw", "", "", false},
		{"0.0.0.0:8443", "", "cert.pem", "key.pem", false},
		{":8443", "pw", "cert.pem", "", false},
	}
	for _, c := range cases {
		if err := checkListen(c.addr, c.password, c.cert, c.key); (err == nil) != c.ok {
			t.Errorf("checkListen(%q, password %t, cert %q, key %q) = %v", c.addr, c.password != "", c.cert, c.key, err)
		}
	}
}

// A page on another site can make a browser send a simple POST to
// 127.0.0.1 (CSRF), spending the keys' credits; one served from a domain
// that resolves to 127.0.0.1 (DNS rebinding) can also read the answer.
// Neither reaches the API.
func TestBrowserAttacksRefused(t *testing.T) {
	h := newTestServer(t)
	body := `{"provider":"phala","model":"openai/gpt-5","messages":[{"role":"user","content":"x"}]}`
	cases := []struct {
		name   string
		method string
		header []string
		want   int
	}{
		{"form-encoded POST", "POST", []string{"Content-Type", "text/plain"}, http.StatusUnsupportedMediaType},
		{"cross-site POST", "POST", []string{"Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site"}, http.StatusForbidden},
		{"cross-site POST, Origin only", "POST", []string{"Origin", "https://evil.example", "Sec-Fetch-Site", ""}, http.StatusForbidden},
		{"rebound host, models", "GET", []string{"Host", "evil.example:8080"}, http.StatusForbidden},
		{"rebound host, chat", "POST", []string{"Host", "evil.example:8080", "Origin", "http://evil.example:8080"}, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := "/api/chat"
			if c.method == "GET" {
				path = "/api/models"
			}
			if w := do(h, c.method, path, body, c.header...); w.Code != c.want {
				t.Fatalf("%d %s, want %d", w.Code, w.Body, c.want)
			}
		})
	}
	// The page itself, at any loopback address, still works.
	for _, host := range []string{"127.0.0.1:8080", "localhost:8080", "[::1]:8080"} {
		w := do(h, "POST", "/api/chat", body, "Host", host, "Origin", "http://"+host)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "MODEL_NOT_ALLOWED") {
			t.Fatalf("%s: %d %s", host, w.Code, w.Body)
		}
	}
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
