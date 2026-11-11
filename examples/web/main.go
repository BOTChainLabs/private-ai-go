// Command web is a chat page for showing the SDK to people. Each answer is
// shown with the proof it passed, and streamed text is marked unverified
// until verification completes. API keys stay on this server; the browser
// never sees them.
//
//	PHALA_API_KEY=... NEARAI_API_KEY=... go run ./examples/web
//	open http://127.0.0.1:8080
//
// PHALA_E2EE=1 also encrypts Phala prompts and answers end to end.
//
// It listens on localhost and answers only requests addressed to a loopback
// name. To serve other machines, pass -addr with -tls-cert and -tls-key, and
// set DEMO_PASSWORD (HTTP basic auth, any user name): every message spends
// the keys' credits. In both cases the API refuses cross-site requests.
package main

import (
	"cmp"
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	privateai "github.com/BOTChainLabs/private-ai-go"
)

//go:embed index.html
var page []byte

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	certFile := flag.String("tls-cert", "", "TLS certificate (PEM); required beyond localhost")
	keyFile := flag.String("tls-key", "", "TLS private key (PEM); required beyond localhost")
	flag.Parse()
	password := os.Getenv("DEMO_PASSWORD")
	if err := checkListen(*addr, password, *certFile, *keyFile); err != nil {
		log.Fatal(err)
	}
	cfg := configFromEnv()
	if len(cfg.Providers) == 0 {
		log.Fatal("set PHALA_API_KEY and/or NEARAI_API_KEY")
	}
	client, err := privateai.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	srv := &http.Server{
		Addr:              *addr,
		Handler:           handler(client, password, isLoopback(*addr)),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if srv.Shutdown(sctx) != nil {
			srv.Close() // cut streams still running
		}
	}()

	if *certFile != "" {
		log.Printf("open https://%s", *addr)
		err = srv.ListenAndServeTLS(*certFile, *keyFile)
	} else {
		log.Printf("open http://%s", *addr)
		err = srv.ListenAndServe()
	}
	if !errors.Is(err, http.ErrServerClosed) {
		client.Close()
		log.Fatal(err)
	}
	<-stopped
	client.Close()
}

// configFromEnv enables each provider whose API key is set, with one model.
func configFromEnv() privateai.Config {
	cfg := privateai.Config{Providers: map[privateai.ProviderID]privateai.ProviderConfig{}}
	for _, p := range []struct {
		id                      privateai.ProviderID
		keyEnv, modelEnv, model string
	}{
		{privateai.Phala, "PHALA_API_KEY", "PHALA_MODEL", "z-ai/glm-5.3"},
		{privateai.NEAR, "NEARAI_API_KEY", "NEARAI_MODEL", "z-ai/glm-5.3-flash"},
	} {
		key := os.Getenv(p.keyEnv)
		if key == "" {
			continue
		}
		cfg.Providers[p.id] = privateai.ProviderConfig{APIKey: key, E2EE: p.id == privateai.Phala && os.Getenv("PHALA_E2EE") == "1"}
		cfg.Models = append(cfg.Models, privateai.ModelEntry{Provider: p.id, Model: cmp.Or(os.Getenv(p.modelEnv), p.model)})
	}
	return cfg
}

// checkListen refuses to serve beyond localhost without a password and TLS:
// every message spends the API keys' credits, and basic auth over plain
// HTTP would send the password, and the answers, in clear.
func checkListen(addr, password, certFile, keyFile string) error {
	if (certFile == "") != (keyFile == "") {
		return errors.New("pass both -tls-cert and -tls-key")
	}
	if !isLoopback(addr) && (password == "" || certFile == "") {
		return errors.New("to listen beyond localhost, set DEMO_PASSWORD and pass -tls-cert and -tls-key: every message spends the API keys' credits")
	}
	return nil
}

// handler is the page and its API with their protections. A browser sends
// a page's cross-site POST without asking (CSRF): those are refused, and the
// API takes JSON only, which a cross-site page cannot send without the
// browser asking first. On localhost, a page on a domain that resolves to
// 127.0.0.1 (DNS rebinding) is same-origin with itself and could read the
// answers, so only loopback names are served; beyond localhost, TLS binds
// the name instead.
func handler(client *privateai.Client, password string, loopback bool) http.Handler {
	h := withPassword(password, (&server{client: client}).routes())
	h = http.NewCrossOriginProtection().Handler(h)
	if loopback {
		h = loopbackHostOnly(h)
	}
	return withHeaders(h)
}

// loopbackHostOnly serves only requests addressed to localhost or a
// loopback IP.
func loopbackHostOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = strings.TrimSuffix(strings.TrimPrefix(r.Host, "["), "]")
		}
		ip := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
			http.Error(w, "this demo serves localhost only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func withPassword(password string, next http.Handler) http.Handler {
	if password == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pw, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(pw), []byte(password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="Private AI demo"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func withHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

type server struct {
	client *privateai.Client
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /api/models", s.models)
	mux.HandleFunc("POST /api/chat", s.chat)
	return mux
}

func (s *server) index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(page)
}

// providerInfo is how the page presents a provider, and what a Verified
// result from it has passed: the SDK returns Verified only after every check.
type providerInfo struct {
	Label   string
	Streams bool // false: the answer arrives in one piece, already verified
	Checks  []check
}

type check struct {
	Title  string
	Detail func(privateai.Evidence) string
}

var providers = map[privateai.ProviderID]providerInfo{
	privateai.Phala: {Label: "Phala", Streams: true, Checks: []check{
		{"TEE hardware", func(e privateai.Evidence) string { return "Intel TDX quote verified." + tcb(e) }},
		{"Approved code", func(e privateai.Evidence) string {
			return "Phala's gateway app " + short(e.AppID) + ", on a pinned dstack OS build, with keys from Phala's KMS."
		}},
		{"Private channel", func(e privateai.Evidence) string {
			if e.E2EE != "" {
				return "TLS is pinned to the key attested inside the TEE, and the prompt and answer are also encrypted end to end (E2EE v2) between this server and the TEE."
			}
			return "TLS is pinned to the key attested inside the TEE, so the prompt is decrypted only there."
		}},
		{"Model in a TEE", func(e privateai.Evidence) string {
			return "The gateway attested the model server it used (session " + short(e.SessionID) + ")."
		}},
		{"Signed answer", func(e privateai.Evidence) string {
			return "Receipt " + e.ReceiptID + ", signed inside the TEE over the exact request and response."
		}},
	}},
	privateai.NEAR: {Label: "NEAR AI", Checks: []check{
		{"TEE hardware", func(e privateai.Evidence) string { return "Intel TDX and NVIDIA GPU attestation verified." + tcb(e) }},
		{"Approved code", func(e privateai.Evidence) string {
			return "NEAR's gateway and model app " + short(e.AppID) + ", on pinned dstack OS builds, with keys from NEAR's KMS."
		}},
		{"Private channel", func(privateai.Evidence) string {
			return "The gateway's TLS key is attested, and the prompt is encrypted end to end to the attested model key."
		}},
		{"Signed answer", func(e privateai.Evidence) string {
			return "Answer " + e.ReceiptID + ", signed by the model's TEE key."
		}},
	}},
}

func tcb(e privateai.Evidence) string {
	if e.TCBStatus == "" {
		return ""
	}
	if len(e.AdvisoryIDs) > 0 {
		return " TCB status " + e.TCBStatus + " (" + strings.Join(e.AdvisoryIDs, ", ") + ")."
	}
	return " TCB status " + e.TCBStatus + "."
}

func short(h string) string {
	if len(h) > 14 {
		return h[:8] + "…"
	}
	return h
}

func (s *server) models(w http.ResponseWriter, _ *http.Request) {
	type model struct {
		Provider privateai.ProviderID `json:"provider"`
		Model    string               `json:"model"`
		Label    string               `json:"label"`
		Streams  bool                 `json:"streams"`
		Checks   []string             `json:"checks"`
	}
	out := []model{}
	for _, m := range s.client.ListModels() {
		info := providers[m.Provider]
		titles := make([]string, len(info.Checks))
		for i, c := range info.Checks {
			titles[i] = c.Title
		}
		out = append(out, model{m.Provider, m.Model, cmp.Or(info.Label, string(m.Provider)), info.Streams, titles})
	}
	writeJSON(w, http.StatusOK, out)
}

const maxMessages = 100

type chatRequest struct {
	Provider privateai.ProviderID `json:"provider"`
	Model    string               `json:"model"`
	Messages []privateai.Message  `json:"messages"`
	Stream   bool                 `json:"stream"`
}

func (r chatRequest) validate() error {
	if len(r.Messages) == 0 || len(r.Messages) > maxMessages {
		return fmt.Errorf("send 1 to %d messages", maxMessages)
	}
	for _, m := range r.Messages {
		if m.Role != "user" && m.Role != "assistant" && m.Role != "system" {
			return fmt.Errorf("unknown role %q", m.Role)
		}
	}
	return nil
}

func (s *server) chat(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		err := &privateai.Error{Code: privateai.CodeInvalidRequest, Message: "send the request as application/json"}
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": errorView(err)})
		return
	}
	var req chatRequest
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req)
	if err == nil {
		err = req.validate()
	}
	if err != nil {
		err = &privateai.Error{Code: privateai.CodeInvalidRequest, Message: err.Error()}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": errorView(err)})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	in := privateai.InferRequest{Provider: req.Provider, Model: req.Model, Messages: req.Messages}
	start := time.Now()
	// done logs the outcome, never the conversation.
	done := func(err error) {
		outcome := "Verified"
		if err != nil {
			outcome = fmt.Sprint(errorView(err)["code"])
		}
		log.Printf("%s %s stream=%t: %s in %d ms", req.Provider, req.Model, req.Stream, outcome, since(start))
	}

	if !req.Stream {
		res, err := s.client.Infer(ctx, in)
		done(err)
		if err != nil {
			writeJSON(w, statusOf(err), map[string]any{"error": errorView(err), "elapsed_ms": since(start)})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"content":      res.Content,
			"usage":        res.Usage,
			"verification": verificationView(&res.Verification),
			"elapsed_ms":   since(start),
		})
		return
	}

	st, err := s.client.Stream(ctx, in)
	if err != nil {
		done(err)
		writeJSON(w, statusOf(err), map[string]any{"error": errorView(err), "elapsed_ms": since(start)})
		return
	}
	defer st.Close()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	rc := http.NewResponseController(w)
	event := func(name string, data any) error {
		b, err := json.Marshal(data)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, b); err != nil {
			return err
		}
		return rc.Flush()
	}
	fail := func(err error) {
		done(err)
		event("error", map[string]any{"error": errorView(err), "elapsed_ms": since(start)})
	}
	// The request is with the attested TEE; reasoning models think before
	// the first delta.
	if event("started", struct{}{}) != nil {
		done(errors.New("browser disconnected"))
		return
	}
	for {
		c, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			fail(err)
			return
		}
		if c.Content != "" && event("delta", map[string]string{"content": c.Content}) != nil {
			done(errors.New("browser disconnected"))
			return
		}
	}
	v, err := st.Verify(ctx)
	if err != nil {
		fail(err)
		return
	}
	done(nil)
	event("verified", map[string]any{"usage": st.Usage(), "verification": verificationView(v), "elapsed_ms": since(start)})
}

// verificationView is what the page shows, and offers for download, about a
// verification. The checks are listed only for a Verified result.
func verificationView(v *privateai.Verification) map[string]any {
	if v == nil {
		return nil
	}
	e := v.Evidence
	out := map[string]any{
		"status":   v.Status,
		"provider": v.Provider,
		"model":    v.Model,
		"route":    v.Route,
		"reasons":  v.Reasons,
		"evidence": map[string]string{
			"tcb_status":    e.TCBStatus,
			"advisory_ids":  strings.Join(e.AdvisoryIDs, ", "),
			"app_id":        e.AppID,
			"compose_hash":  e.ComposeHash,
			"os_image_hash": e.OSImageHash,
			"keyset_digest": e.KeysetDigest,
			"receipt_id":    e.ReceiptID,
			"session_id":    e.SessionID,
		},
	}
	if v.Status == privateai.Verified {
		var checks []map[string]string
		for _, c := range providers[v.Provider].Checks {
			checks = append(checks, map[string]string{"title": c.Title, "detail": c.Detail(e)})
		}
		out["checks"] = checks
	}
	if json.Valid(e.Receipt) {
		out["receipt"] = e.Receipt
	}
	if json.Valid(e.Keyset) {
		out["keyset"] = e.Keyset
	}
	return out
}

// reasons explains each error code in plain words; the SDK's message
// follows it on the page.
var reasons = map[string]string{
	privateai.CodeInvalidRequest:      "The request was invalid, so nothing was sent.",
	privateai.CodeModelNotAllowed:     "This model is not enabled, so nothing was sent.",
	privateai.CodeAttestationFailed:   "The TEE or the code it runs did not check out, so the answer was refused.",
	privateai.CodeTLSPinMismatch:      "The server's TLS key is not the attested one, so nothing was sent.",
	privateai.CodeReceiptInvalid:      "The signature over the answer did not check out, so the answer was refused.",
	privateai.CodeRouteNotTEE:         "The request was not served inside a TEE, so the answer was refused.",
	privateai.CodeEvidenceUnavailable: "The proof could not be fetched, so the answer was refused.",
	privateai.CodeVerifierUnavailable: "An attestation service (Intel, or NVIDIA for GPUs) could not be reached, so the answer was refused.",
	privateai.CodeProviderError:       "The provider returned an error, such as a bad key, low balance or rate limit.",
}

func errorView(err error) map[string]any {
	var e *privateai.Error
	if !errors.As(err, &e) {
		return map[string]any{"code": "ERROR", "reason": "The request failed.", "message": err.Error()}
	}
	return map[string]any{
		"code":         e.Code,
		"reason":       cmp.Or(reasons[e.Code], "The request failed."),
		"message":      e.Error(),
		"verification": verificationView(e.Verification),
	}
}

// statusOf is 400 for a request the SDK refused before sending, 502 otherwise.
func statusOf(err error) int {
	var e *privateai.Error
	if errors.As(err, &e) && (e.Code == privateai.CodeInvalidRequest || e.Code == privateai.CodeModelNotAllowed) {
		return http.StatusBadRequest
	}
	return http.StatusBadGateway
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func since(t time.Time) int64 { return time.Since(t).Milliseconds() }
