// Package canon produces the JCS (RFC 8785) form of ACI documents.
//
// ACI restricts its documents to ASCII member names and integer numbers
// (spec Appendix A). Under those constraints JCS is compact JSON with member
// names sorted bytewise and strings escaped as ECMAScript's JSON.stringify
// does. Decode enforces the constraints, and also rejects duplicate member
// names, so that what a verifier reads is exactly what was signed.
package canon

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
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
	var b bytes.Buffer
	if err := write(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func write(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		b.WriteByte('{')
		for i, k := range slices.Sorted(maps.Keys(t)) { // ASCII names: byte order is JCS order
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := write(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := write(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case string:
		writeString(b, t)
	case json.Number:
		b.WriteString(t.String())
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case nil:
		b.WriteString("null")
	default:
		return fmt.Errorf("canon: unsupported value of type %T", v)
	}
	return nil
}

// writeString escapes like JSON.stringify (RFC 8785 §3.2.2.2): the quote,
// the backslash and control characters only. encoding/json differs: it
// always escapes U+2028 and U+2029.
func writeString(b *bytes.Buffer, s string) {
	const hexDigits = "0123456789abcdef"
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if c < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte(hexDigits[c>>4])
				b.WriteByte(hexDigits[c&0xf])
			} else {
				b.WriteByte(c) // UTF-8 bytes are copied as is
			}
		}
	}
	b.WriteByte('"')
}

// Canonicalize re-encodes a JSON document in canonical form.
func Canonicalize(data []byte) ([]byte, error) {
	v, err := Decode(data)
	if err != nil {
		return nil, err
	}
	return Marshal(v)
}
