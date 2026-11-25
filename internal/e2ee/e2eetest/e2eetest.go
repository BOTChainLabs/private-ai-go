// Package e2eetest is the service side of E2EE v2, for tests: it decrypts
// requests and encrypts responses the way the reference gateway does
// (src/aggregator/service/e2ee*.rs at commit 22d08e24).
package e2eetest

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BOTChainLabs/private-ai-go/internal/e2ee"
	"github.com/BOTChainLabs/private-ai-go/internal/serdejson"
)

// Service holds the attested E2EE key and the replay cache.
type Service struct {
	key *ecdh.PrivateKey

	mu   sync.Mutex
	seen map[string]bool
}

func NewService(seed byte) *Service {
	k, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{seed}, 32))
	if err != nil {
		panic(err)
	}
	return &Service{key: k, seen: map[string]bool{}}
}

// PublicHex is the key to publish in the keyset.
func (s *Service) PublicHex() string { return hex.EncodeToString(s.key.PublicKey().Bytes()) }

// Exchange is one decrypted request, used to encrypt its response.
type Exchange struct {
	client       *ecdh.PublicKey
	model, nonce string
	ts           int64
	// Hashed is the restored request as the gateway serializes it, the
	// bytes its receipt hashes.
	Hashed []byte
}

// OpenRequest checks the E2EE v2 headers and decrypts a chat request.
func (s *Service) OpenRequest(h http.Header, body []byte, now time.Time) (*Exchange, error) {
	if h.Get("X-E2EE-Version") != e2ee.Version {
		return nil, errors.New("e2ee_invalid_version")
	}
	if !strings.EqualFold(strings.TrimPrefix(h.Get("X-Model-Pub-Key"), "0x"), s.PublicHex()) {
		return nil, errors.New("e2ee_model_key_mismatch")
	}
	nonce := h.Get("X-E2EE-Nonce")
	if len(nonce) != 64 {
		return nil, errors.New("e2ee_invalid_nonce")
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return nil, errors.New("e2ee_invalid_nonce")
	}
	ts, err := strconv.ParseInt(h.Get("X-E2EE-Timestamp"), 10, 64)
	if err != nil || ts < now.Unix()-300 || ts > now.Unix()+300 {
		return nil, errors.New("e2ee_invalid_timestamp")
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(h.Get("X-Client-Pub-Key"), "0x"))
	if err != nil {
		return nil, errors.New("e2ee_invalid_public_key")
	}
	client, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, errors.New("e2ee_invalid_public_key")
	}
	s.mu.Lock()
	replay := hex.EncodeToString(raw) + strings.ToLower(nonce)
	dup := s.seen[replay]
	s.seen[replay] = true
	s.mu.Unlock()
	if dup {
		return nil, errors.New("e2ee_replay_detected")
	}

	doc, err := serdejson.Parse(body)
	if err != nil {
		return nil, err
	}
	root, _ := doc.(*serdejson.Object)
	if root == nil {
		return nil, errors.New("e2ee_decryption_failed")
	}
	m, _ := root.Get("model")
	model, ok := m.(string)
	if !ok {
		return nil, errors.New("e2ee_invalid_payload_model")
	}
	x := &Exchange{client: client, model: model, nonce: nonce, ts: ts}
	open := func(ct, path string) (string, error) {
		pt, err := decrypt(s.key, ct, e2ee.AAD(e2ee.RequestPurpose, model, path, nonce, ts, nil))
		if err != nil {
			return "", fmt.Errorf("e2ee_decryption_failed: %s: %w", path, err)
		}
		return string(pt), nil
	}
	msgs, _ := root.Get("messages")
	list, _ := msgs.([]any)
	count := 0
	for i, msg := range list {
		obj, ok := msg.(*serdejson.Object)
		if !ok {
			continue
		}
		switch c, _ := obj.Get("content"); c := c.(type) {
		case string:
			pt, err := open(c, fmt.Sprintf("messages.%d.content", i))
			if err != nil {
				return nil, err
			}
			// A plaintext that parses as an array is restored as structured
			// content.
			if v, err := serdejson.Parse([]byte(pt)); err == nil {
				if arr, ok := v.([]any); ok {
					obj.Set("content", arr)
					count++
					continue
				}
			}
			obj.Set("content", pt)
			count++
		case []any:
			for j, p := range c {
				part, ok := p.(*serdejson.Object)
				if !ok {
					continue
				}
				if t, _ := part.Get("type"); t != "text" {
					continue
				}
				if ct, ok := part.Get("text"); ok {
					pt, err := open(ct.(string), fmt.Sprintf("messages.%d.content.%d.text", i, j))
					if err != nil {
						return nil, err
					}
					part.Set("text", pt)
					count++
				}
			}
		}
	}
	if count == 0 {
		return nil, errors.New("e2ee_decryption_failed: no encrypted field")
	}
	if x.Hashed, err = serdejson.Marshal(root); err != nil {
		return nil, err
	}
	return x, nil
}

// SealResponse encrypts a buffered chat completion's generated content.
func (x *Exchange) SealResponse(body []byte) ([]byte, error) {
	return x.seal(body, "message")
}

// SealEvent encrypts one streamed event. An empty content delta is dropped,
// as the gateway does.
func (x *Exchange) SealEvent(data []byte) ([]byte, error) {
	return x.seal(data, "delta")
}

func (x *Exchange) seal(body []byte, member string) ([]byte, error) {
	doc, err := serdejson.Parse(body)
	if err != nil {
		return nil, err
	}
	root := doc.(*serdejson.Object)
	id, _ := root.Get("id")
	respID, _ := id.(string)
	choices, _ := root.Get("choices")
	list, _ := choices.([]any)
	for pos, c := range list {
		choice := c.(*serdejson.Object)
		idx := strconv.Itoa(pos)
		if n, ok := choice.Get("index"); ok {
			idx = string(n.(serdejson.Number))
		}
		m, _ := choice.Get(member)
		msg, ok := m.(*serdejson.Object)
		if !ok {
			continue
		}
		if member == "delta" {
			if c, _ := msg.Get("content"); c == "" {
				msg = without(msg, "content")
				choice.Set(member, msg)
			}
		}
		for _, name := range []string{"content", "reasoning", "reasoning_content"} {
			v, ok := msg.Get(name)
			s, isString := v.(string)
			if !ok || !isString {
				continue
			}
			path := fmt.Sprintf("choices.%s.%s.%s", idx, member, name)
			ct, err := encrypt(x.client, []byte(s), e2ee.AAD(e2ee.ResponsePurpose, x.model, path, x.nonce, x.ts, &respID))
			if err != nil {
				return nil, err
			}
			msg.Set(name, ct)
		}
	}
	return serdejson.Marshal(root)
}

func without(o *serdejson.Object, key string) *serdejson.Object {
	out := &serdejson.Object{}
	for _, k := range o.Keys() {
		if k != key {
			v, _ := o.Get(k)
			out.Set(k, v)
		}
	}
	return out
}

func encrypt(to *ecdh.PublicKey, plaintext, aad []byte) (string, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	aead, err := aeadFor(eph, to)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, 12)
	rand.Read(nonce)
	out := append(eph.PublicKey().Bytes(), nonce...)
	return hex.EncodeToString(aead.Seal(out, nonce, plaintext, aad)), nil
}

func decrypt(key *ecdh.PrivateKey, ctHex string, aad []byte) ([]byte, error) {
	blob, err := hex.DecodeString(ctHex)
	if err != nil || len(blob) < 32+12+16 {
		return nil, errors.New("malformed ciphertext")
	}
	eph, err := ecdh.X25519().NewPublicKey(blob[:32])
	if err != nil {
		return nil, err
	}
	aead, err := aeadFor(key, eph)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, blob[32:44], blob[44:], aad)
}

func aeadFor(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) (cipher.AEAD, error) {
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, e2ee.HKDFInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
