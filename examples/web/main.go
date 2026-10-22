// Command web is a small chat page on top of the SDK. Each answer is shown
// with the verification it passed, and streamed answers are marked
// unverified until their verification completes. API keys stay on this
// server; the browser never sees them.
//
//	PHALA_API_KEY=... NEARAI_API_KEY=... go run ./examples/web
//	open http://localhost:8080
//
// It listens on localhost only. To expose it, set -addr and DEMO_PASSWORD
// (HTTP basic auth, any user name): every request spends the keys' credits.
package main

import (
	"context"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	privateai "github.com/BOTChainLabs/private-ai-go"
)

//go:embed index.html
var page []byte

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "listen address")
	flag.Parse()

	cfg := privateai.Config{Providers: map[privateai.ProviderID]privateai.ProviderConfig{}}
	add := func(id privateai.ProviderID, keyEnv, modelEnv, model string) {
		if key := os.Getenv(keyEnv); key != "" {
			cfg.Providers[id] = privateai.ProviderConfig{APIKey: key}
			if m := os.Getenv(modelEnv); m != "" {
				model = m
			}
			cfg.Models = append(cfg.Models, privateai.ModelEntry{Provider: id, Model: model})
		}
	}
	add(privateai.Phala, "PHALA_API_KEY", "PHALA_MODEL", "z-ai/glm-5.3")
	add(privateai.NEAR, "NEARAI_API_KEY", "NEARAI_MODEL", "z-ai/glm-5.3-flash")
	if len(cfg.Providers) == 0 {
		log.Fatal("set PHALA_API_KEY and/or NEARAI_API_KEY")
	}
	client, err := privateai.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	s := &server{client: client, password: os.Getenv("DEMO_PASSWORD")}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /api/models", s.models)
	mux.HandleFunc("POST /api/chat", s.chat)

	srv := &http.Server{Addr: *addr, Handler: s.auth(mux), ReadHeaderTimeout: 10 * time.Second}
	log.Printf("open http://%s", *addr)
	log.Fatal(srv.ListenAndServe())
}

type server struct {
	client   *privateai.Client
	password string
}

func (s *server) auth(next http.Handler) http.Handler {
	if s.password == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pw, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(pw), []byte(s.password)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="private-ai demo"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *server) index(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(page)
}

func (s *server) models(w http.ResponseWriter, _ *http.Request) {
	type model struct {
		Provider privateai.ProviderID `json:"provider"`
		Model    string               `json:"model"`
	}
	var out []model
	for _, m := range s.client.ListModels() {
		out = append(out, model{m.Provider, m.Model})
	}
	writeJSON(w, http.StatusOK, out)
}

type chatRequest struct {
	Provider privateai.ProviderID `json:"provider"`
	Model    string               `json:"model"`
	Messages []privateai.Message  `json:"messages"`
	Stream   bool                 `json:"stream"`
}

func (s *server) chat(w http.ResponseWriter, r *http.Request) {
	var req chatRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "INVALID_REQUEST", "message": err.Error()}})
		return
	}
	for _, m := range req.Messages {
		if m.Role != "user" && m.Role != "assistant" && m.Role != "system" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": map[string]string{"code": "INVALID_REQUEST", "message": "unknown role " + m.Role}})
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	in := privateai.InferRequest{Provider: req.Provider, Model: req.Model, Messages: req.Messages}
	start := time.Now()

	if !req.Stream {
		res, err := s.client.Infer(ctx, in)
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
		writeJSON(w, statusOf(err), map[string]any{"error": errorView(err), "elapsed_ms": since(start)})
		return
	}
	defer st.Close()
	flusher, _ := w.(http.Flusher)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	send := func(event string, data any) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		if flusher != nil {
			flusher.Flush()
		}
	}
	for {
		c, err := st.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			send("error", map[string]any{"error": errorView(err), "elapsed_ms": since(start)})
			return
		}
		if c.Content != "" {
			send("delta", map[string]string{"content": c.Content})
		}
	}
	v, err := st.Verify(ctx)
	if err != nil {
		send("error", map[string]any{"error": errorView(err), "elapsed_ms": since(start)})
		return
	}
	send("verified", map[string]any{"usage": st.Usage(), "verification": verificationView(v), "elapsed_ms": since(start)})
}

// verificationView is what the page shows about a verification.
func verificationView(v *privateai.Verification) map[string]any {
	if v == nil {
		return nil
	}
	e := v.Evidence
	return map[string]any{
		"status":        v.Status,
		"provider":      v.Provider,
		"model":         v.Model,
		"route":         v.Route,
		"reasons":       v.Reasons,
		"tcb_status":    e.TCBStatus,
		"app_id":        e.AppID,
		"compose_hash":  e.ComposeHash,
		"os_image_hash": e.OSImageHash,
		"keyset_digest": e.KeysetDigest,
		"receipt_id":    e.ReceiptID,
		"session_id":    e.SessionID,
		"receipt_bytes": len(e.Receipt),
	}
}

func errorView(err error) map[string]any {
	var e *privateai.Error
	if !errors.As(err, &e) {
		return map[string]any{"code": "ERROR", "message": err.Error()}
	}
	return map[string]any{"code": e.Code, "message": e.Error(), "verification": verificationView(e.Verification)}
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
