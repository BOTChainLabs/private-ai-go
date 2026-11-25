package e2ee_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BOTChainLabs/private-ai-go/internal/e2ee"
	"github.com/BOTChainLabs/private-ai-go/internal/e2ee/e2eetest"
)

// The byte-exact AAD vectors of spec/e2ee-v2-test-vectors.md.
func TestAADVectors(t *testing.T) {
	const nonce = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	req := e2ee.AAD(e2ee.RequestPurpose, "demo-model", "messages.0.content", nonce, 1750000000, nil)
	if want := `{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"messages.0.content","model":"demo-model","nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","purpose":"aci.e2ee.request.v2","ts":1750000000}`; string(req) != want {
		t.Fatalf("request AAD\n got %s\nwant %s", req, want)
	}
	id := "chatcmpl-123"
	resp := e2ee.AAD(e2ee.ResponsePurpose, "demo-model", "choices.0.message.content", nonce, 1750000000, &id)
	if want := `{"algo":"x25519-aes-256-gcm-hkdf-sha256","field":"choices.0.message.content","id":"chatcmpl-123","model":"demo-model","nonce":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f","purpose":"aci.e2ee.response.v2","ts":1750000000}`; string(resp) != want {
		t.Fatalf("response AAD\n got %s\nwant %s", resp, want)
	}
	// The vectors' service key, from the private seed 32 x 0x03.
	if got := e2eetest.NewService(0x03).PublicHex(); got != "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22" {
		t.Fatalf("service key %s", got)
	}
}

const chatBody = `{"messages":[{"role":"system","content":"be brief"},{"role":"user","content":"hi <there>  "},{"role":"user","content":" [1, 2] is an array"}],"model":"z-ai/glm-5.3","provider":{"aci_verified":true},"stream":false,"temperature":0.7,"max_tokens":512}`

func seal(t *testing.T, svc *e2eetest.Service, body string) (*e2ee.Request, http.Header, []byte, *e2eetest.Exchange) {
	t.Helper()
	r, err := e2ee.New(svc.PublicHex(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	wire, hashed, err := r.SealChat([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{}
	r.SetHeaders(h)
	x, err := svc.OpenRequest(h, wire, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x.Hashed, hashed) {
		t.Fatalf("the service hashes\n%s\nthe client predicted\n%s", x.Hashed, hashed)
	}
	return r, h, wire, x
}

func TestRequestRoundTrip(t *testing.T) {
	svc := e2eetest.NewService(0x03)
	_, h, wire, x := seal(t, svc, chatBody)
	for _, secret := range []string{"be brief", "<there>", "is an array"} {
		if bytes.Contains(wire, []byte(secret)) {
			t.Errorf("wire body carries %q in plaintext", secret)
		}
	}
	if !bytes.Contains(wire, []byte(`"temperature":0.7,"max_tokens":512`)) {
		t.Errorf("other parameters changed: %s", wire)
	}
	// Content that reads as a JSON array travels as a text part.
	if !bytes.Contains(x.Hashed, []byte(`{"role":"user","content":[{"type":"text","text":" [1, 2] is an array"}]}`)) {
		t.Errorf("array-like content not sent as a text part: %s", x.Hashed)
	}
	for k, want := range map[string]int{"X-E2EE-Version": 1, "X-Client-Pub-Key": 64, "X-Model-Pub-Key": 64, "X-E2EE-Nonce": 64, "X-E2EE-Timestamp": 10} {
		if got := len(h.Get(k)); got != want {
			t.Errorf("header %s has %d characters, want %d", k, got, want)
		}
	}
	if h.Get("X-Signing-Algo") != "" {
		t.Error("X-Signing-Algo selects the legacy protocol and must not be sent")
	}
}

func TestEveryFieldHasFreshKeyAndNonce(t *testing.T) {
	svc := e2eetest.NewService(0x03)
	_, _, wire, _ := seal(t, svc, chatBody)
	var body struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	json.Unmarshal(wire, &body)
	var a, b string
	json.Unmarshal(body.Messages[0].Content, &a)
	json.Unmarshal(body.Messages[1].Content, &b)
	ra, _ := hex.DecodeString(a)
	rb, _ := hex.DecodeString(b)
	if bytes.Equal(ra[:32], rb[:32]) || bytes.Equal(ra[32:44], rb[32:44]) {
		t.Fatal("two fields share an ephemeral key or a nonce")
	}
}

func TestResponseRoundTrip(t *testing.T) {
	svc := e2eetest.NewService(0x03)
	r, _, _, x := seal(t, svc, chatBody)
	resp := `{"id":"chatcmpl-9","choices":[{"index":0,"message":{"role":"assistant","content":"secret answer","reasoning_content":"secret thought"}}],"usage":{"total_tokens":7}}`
	enc, err := x.SealResponse([]byte(resp))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, []byte("secret")) {
		t.Fatalf("service did not encrypt: %s", enc)
	}
	got, err := r.OpenChat(enc)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != resp {
		t.Fatalf("decrypted\n%s\nwant\n%s", got, resp)
	}
}

func TestStreamEventRoundTrip(t *testing.T) {
	svc := e2eetest.NewService(0x03)
	r, _, _, x := seal(t, svc, chatBody)
	for _, ev := range []string{
		`{"id":"c1","choices":[{"index":0,"delta":{"role":"assistant","content":"hel"}}]}`,
		`{"id":"c1","choices":[{"index":0,"delta":{"reasoning":"why"}}]}`,
		`{"id":"c1","choices":[],"usage":{"total_tokens":3}}`,
	} {
		enc, err := x.SealEvent([]byte(ev))
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.OpenChatEvent(enc)
		if err != nil || string(got) != ev {
			t.Fatalf("event %s: got %s, %v", ev, got, err)
		}
	}
}

func TestResponseTamperingIsRejected(t *testing.T) {
	svc := e2eetest.NewService(0x03)
	r, _, _, x := seal(t, svc, chatBody)
	enc, _ := x.SealResponse([]byte(`{"id":"a","choices":[{"index":0,"message":{"content":"answer"}}]}`))
	cases := map[string][]byte{
		// The ciphertext is bound to the response id and the field path.
		"other id":     bytes.Replace(enc, []byte(`"id":"a"`), []byte(`"id":"b"`), 1),
		"other choice": bytes.Replace(enc, []byte(`"index":0`), []byte(`"index":1`), 1),
		"plaintext":    []byte(`{"id":"a","choices":[{"index":0,"message":{"content":"answer"}}]}`),
		"not a string": []byte(`{"id":"a","choices":[{"index":0,"message":{"content":42}}]}`),
	}
	for name, body := range cases {
		if _, err := r.OpenChat(body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Another request's key cannot read it.
	other, _, _, _ := seal(t, svc, chatBody)
	if _, err := other.OpenChat(enc); err == nil {
		t.Error("another request decrypted the response")
	}
}

func TestReplayIsRejectedByTheService(t *testing.T) {
	svc := e2eetest.NewService(0x03)
	_, h, wire, _ := seal(t, svc, chatBody)
	if _, err := svc.OpenRequest(h, wire, time.Now()); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("replayed request: %v", err)
	}
}

func TestSealChatRejects(t *testing.T) {
	r, _ := e2ee.New(e2eetest.NewService(0x03).PublicHex(), time.Now())
	for name, body := range map[string]string{
		"no model":       `{"messages":[{"role":"user","content":"x"}]}`,
		"no content":     `{"model":"m","messages":[{"role":"user"}]}`,
		"not a string":   `{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"x"}]}]}`,
		"duplicate keys": `{"model":"m","model":"n","messages":[{"role":"user","content":"x"}]}`,
		"huge number":    `{"model":"m","messages":[{"role":"user","content":"x"}],"seed":1e400}`,
	} {
		if _, _, err := r.SealChat([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := e2ee.New("abcd", time.Now()); err == nil {
		t.Error("short service key accepted")
	}
}
