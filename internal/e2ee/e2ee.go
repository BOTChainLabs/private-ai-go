// Package e2ee is the client side of E2EE v2, the content encryption an ACI
// gateway terminates inside its TEE:
// https://github.com/Dstack-TEE/private-ai-gateway/blob/main/spec/e2ee-v2.md
//
// Message content is encrypted to the gateway's attested key, and generated
// content comes back encrypted to a fresh key of this request. Only the
// X25519 suite is implemented: the spec recommends it, and the reference
// gateway publishes it.
package e2ee

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/BOTChainLabs/private-ai-go/internal/canon"
	"github.com/BOTChainLabs/private-ai-go/internal/serdejson"
)

const (
	// Version is the E2EE protocol version this package speaks.
	Version = "2"
	// Algo is the cipher suite, as named in a keyset's e2ee_public_keys.
	Algo = "x25519-aes-256-gcm-hkdf-sha256"

	// HKDFInfo, RequestPurpose and ResponsePurpose are the suite's key
	// derivation info and the AAD purposes (§10).
	HKDFInfo        = "aci.e2ee.v2.x25519"
	RequestPurpose  = "aci.e2ee.request.v2"
	ResponsePurpose = "aci.e2ee.response.v2"

	keyLen   = 32
	nonceLen = 12
	tagLen   = 16
)

// Request is the E2EE context of one request: the service key, a fresh
// client key, the replay nonce and the timestamp. Responses are decrypted
// with the same Request.
type Request struct {
	service    *ecdh.PublicKey
	serviceHex string
	client     *ecdh.PrivateKey
	nonce      string
	ts         int64
	model      string // set by SealChat
}

// New starts a request encrypted to serviceKeyHex, the service's attested
// X25519 key (hex, optional 0x).
func New(serviceKeyHex string, now time.Time) (*Request, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(serviceKeyHex, "0x"))
	if err != nil || len(raw) != keyLen {
		return nil, fmt.Errorf("e2ee: service key is not a hex X25519 key")
	}
	service, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("e2ee: service key: %w", err)
	}
	client, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 32)
	rand.Read(nonce)
	return &Request{
		service:    service,
		serviceHex: serviceKeyHex,
		client:     client,
		nonce:      hex.EncodeToString(nonce),
		ts:         now.Unix(),
	}, nil
}

// SetHeaders adds the five E2EE v2 request headers (§3.1).
func (r *Request) SetHeaders(h http.Header) {
	h.Set("X-E2EE-Version", Version)
	h.Set("X-Client-Pub-Key", hex.EncodeToString(r.client.PublicKey().Bytes()))
	h.Set("X-Model-Pub-Key", r.serviceHex)
	h.Set("X-E2EE-Nonce", r.nonce)
	h.Set("X-E2EE-Timestamp", strconv.FormatInt(r.ts, 10))
}

// SealChat encrypts the content of every message of a chat completion
// request. It returns the body to send and the body the gateway hashes into
// its receipt once it has decrypted the request (§8).
//
// Content is encrypted whole, as messages.{m}.content. Content that could
// read as a JSON array is sent as one text part instead, because the gateway
// restores a whole-content plaintext that parses as an array as structured
// content.
func (r *Request) SealChat(body []byte) (wire, hashed []byte, err error) {
	doc, err := serdejson.Parse(body)
	if err != nil {
		return nil, nil, err
	}
	root, ok := doc.(*serdejson.Object)
	if !ok {
		return nil, nil, errors.New("e2ee: request is not a JSON object")
	}
	model, _ := root.Get("model")
	if r.model, ok = model.(string); !ok {
		return nil, nil, errors.New("e2ee: request has no model")
	}
	msgs, _ := root.Get("messages")
	list, _ := msgs.([]any)

	type field struct {
		in        *serdejson.Object
		key, path string
		plaintext string
	}
	var fields []field
	for m, msg := range list {
		obj, ok := msg.(*serdejson.Object)
		if !ok {
			return nil, nil, fmt.Errorf("e2ee: message %d is not an object", m)
		}
		content, ok := obj.Get("content")
		if !ok {
			continue
		}
		text, ok := content.(string)
		if !ok {
			return nil, nil, fmt.Errorf("e2ee: message %d content is not a string", m)
		}
		if !strings.HasPrefix(strings.TrimLeft(text, " \t\n\r"), "[") {
			fields = append(fields, field{obj, "content", fmt.Sprintf("messages.%d.content", m), text})
			continue
		}
		part := &serdejson.Object{}
		part.Set("type", "text")
		part.Set("text", text)
		obj.Set("content", []any{part})
		fields = append(fields, field{part, "text", fmt.Sprintf("messages.%d.content.0.text", m), text})
	}
	if len(fields) == 0 {
		return nil, nil, errors.New("e2ee: request has no message content to encrypt")
	}

	if hashed, err = serdejson.Marshal(root); err != nil {
		return nil, nil, err
	}
	for _, f := range fields {
		ct, err := r.seal(f.path, []byte(f.plaintext))
		if err != nil {
			return nil, nil, err
		}
		f.in.Set(f.key, ct)
	}
	if wire, err = serdejson.Marshal(root); err != nil {
		return nil, nil, err
	}
	return wire, hashed, nil
}

// OpenChat decrypts the generated content of a buffered chat completion and
// returns the response with those fields in plaintext. Every listed field
// that is present must decrypt (§5).
func (r *Request) OpenChat(body []byte) ([]byte, error) {
	return r.open(body, "message", []string{"content", "reasoning", "reasoning_content"}, true)
}

// OpenChatEvent decrypts the generated content of one streamed chat
// completion event.
func (r *Request) OpenChatEvent(data []byte) ([]byte, error) {
	return r.open(data, "delta", []string{"content", "reasoning", "reasoning_content"}, false)
}

func (r *Request) open(body []byte, member string, names []string, audio bool) ([]byte, error) {
	doc, err := serdejson.Parse(body)
	if err != nil {
		return nil, err
	}
	root, ok := doc.(*serdejson.Object)
	if !ok {
		return nil, errors.New("e2ee: response is not a JSON object")
	}
	id, _ := root.Get("id")
	respID, _ := id.(string)
	choices, _ := root.Get("choices")
	list, _ := choices.([]any)
	for pos, c := range list {
		choice, ok := c.(*serdejson.Object)
		if !ok {
			continue
		}
		prefix := fmt.Sprintf("choices.%s.%s.", choiceIndex(choice, pos), member)
		m, _ := choice.Get(member)
		msg, ok := m.(*serdejson.Object)
		if !ok {
			continue
		}
		for _, name := range names {
			if err := r.openField(msg, name, prefix+name, respID); err != nil {
				return nil, err
			}
		}
		if !audio {
			continue
		}
		if a, ok := msg.Get("audio"); ok {
			if obj, ok := a.(*serdejson.Object); ok {
				if err := r.openField(obj, "data", prefix+"audio.data", respID); err != nil {
					return nil, err
				}
			}
		}
	}
	return serdejson.Marshal(root)
}

// choiceIndex is the field-path index of a choice: its index member when it
// is an unsigned integer, else its position (§5).
func choiceIndex(choice *serdejson.Object, pos int) string {
	if v, ok := choice.Get("index"); ok {
		if n, ok := v.(serdejson.Number); ok {
			if _, err := strconv.ParseUint(string(n), 10, 64); err == nil {
				return string(n)
			}
		}
	}
	return strconv.Itoa(pos)
}

func (r *Request) openField(in *serdejson.Object, key, path, respID string) error {
	v, ok := in.Get(key)
	if !ok || v == nil {
		return nil
	}
	ct, ok := v.(string)
	if !ok {
		return fmt.Errorf("e2ee: %s is not a ciphertext", path)
	}
	pt, err := r.decrypt(ct, r.aad(ResponsePurpose, path, &respID))
	if err != nil {
		return fmt.Errorf("e2ee: %s: %w", path, err)
	}
	in.Set(key, string(pt))
	return nil
}

// seal encrypts one request field to the service key under a fresh
// ephemeral key and nonce (§4).
func (r *Request) seal(path string, plaintext []byte) (string, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	aead, err := newAEAD(eph, r.service)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceLen)
	rand.Read(nonce)
	out := append(eph.PublicKey().Bytes(), nonce...)
	out = aead.Seal(out, nonce, plaintext, r.aad(RequestPurpose, path, nil))
	return hex.EncodeToString(out), nil
}

// decrypt opens ephemeral_public_key || nonce || ciphertext || tag (hex).
func (r *Request) decrypt(ctHex string, aad []byte) ([]byte, error) {
	blob, err := hex.DecodeString(strings.TrimPrefix(ctHex, "0x"))
	if err != nil || len(blob) < keyLen+nonceLen+tagLen {
		return nil, errors.New("malformed ciphertext")
	}
	eph, err := ecdh.X25519().NewPublicKey(blob[:keyLen])
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(r.client, eph)
	if err != nil {
		return nil, err
	}
	pt, err := aead.Open(nil, blob[keyLen:keyLen+nonceLen], blob[keyLen+nonceLen:], aad)
	if err != nil {
		return nil, errors.New("authentication failed")
	}
	return pt, nil
}

// newAEAD derives the field key: HKDF-SHA256 without salt over the X25519
// shared secret, for AES-256-GCM.
func newAEAD(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) (cipher.AEAD, error) {
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, err
	}
	key, err := hkdf.Key(sha256.New, shared, nil, HKDFInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// aad is the JCS associated data of a field (§6). Response fields also bind
// the response id.
func (r *Request) aad(purpose, path string, respID *string) []byte {
	return AAD(purpose, r.model, path, r.nonce, r.ts, respID)
}

// AAD builds the associated data of a field: the JCS form of its purpose,
// suite, request model, field path, nonce and timestamp, and for a response
// field the response id.
func AAD(purpose, model, path, nonce string, ts int64, respID *string) []byte {
	doc := map[string]any{
		"purpose": purpose,
		"algo":    Algo,
		"model":   model,
		"field":   path,
		"nonce":   nonce,
		"ts":      json.Number(strconv.FormatInt(ts, 10)),
	}
	if respID != nil {
		doc["id"] = *respID
	}
	b, _ := canon.Marshal(doc)
	return b
}
