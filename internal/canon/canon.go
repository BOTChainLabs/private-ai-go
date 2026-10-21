// Package canon produces the JCS (RFC 8785) form of ACI documents.
//
// ACI restricts its documents to ASCII member names and integer numbers
// (spec Appendix A). Under those constraints JCS is compact JSON with
// lexicographically sorted member names, which encoding/json produces for
// maps. Decode enforces the constraints, and also rejects duplicate member
// names, so that what a verifier reads is exactly what was signed.
package canon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Decode parses exactly one JSON value into maps, slices, strings, bools,
// nil and json.Number. It rejects duplicate member names, non-ASCII member
// names, non-integer numbers and trailing data.
func Decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, fmt.Errorf("canon: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("canon: trailing data after JSON value")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key := kt.(string)
				if !isASCII(key) {
					return nil, fmt.Errorf("non-ASCII member name %q", key)
				}
				if _, dup := obj[key]; dup {
					return nil, fmt.Errorf("duplicate member name %q", key)
				}
				if obj[key], err = decodeValue(dec); err != nil {
					return nil, err
				}
			}
			_, err := dec.Token() // '}'
			return obj, err
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			_, err := dec.Token() // ']'
			return arr, err
		}
		return nil, fmt.Errorf("unexpected %v", t)
	case json.Number:
		if strings.ContainsAny(string(t), ".eE") || t == "-0" {
			return nil, fmt.Errorf("non-integer number %s", t)
		}
		return t, nil
	default: // string, bool, nil
		return t, nil
	}
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// Marshal returns the canonical form of a value produced by Decode.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// Canonicalize re-encodes a JSON document in canonical form.
func Canonicalize(data []byte) ([]byte, error) {
	v, err := Decode(data)
	if err != nil {
		return nil, err
	}
	return Marshal(v)
}
