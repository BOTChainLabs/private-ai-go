// Package serdejson reads and writes JSON the way the Private AI Gateway
// does: Rust's serde_json with its preserve_order and float_roundtrip
// features. Member order is kept, strings are escaped minimally, and
// numbers are written as serde_json writes the value it parsed.
//
// An E2EE gateway hashes the request it decrypted after serializing it again
// (E2EE v2 §8). A client that writes its request with this package can
// predict those bytes: Marshal(Parse(Marshal(v))) == Marshal(v).
package serdejson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/BOTChainLabs/private-ai-go/internal/canon"
)

// Object is a JSON object that keeps its members in order.
type Object struct {
	keys []string
	vals []any
}

// Get returns the value of a member.
func (o *Object) Get(key string) (any, bool) {
	for i, k := range o.keys {
		if k == key {
			return o.vals[i], true
		}
	}
	return nil, false
}

// Keys returns the member names in order.
func (o *Object) Keys() []string { return append([]string(nil), o.keys...) }

// Set replaces a member's value in place, or appends the member.
func (o *Object) Set(key string, v any) {
	for i, k := range o.keys {
		if k == key {
			o.vals[i] = v
			return
		}
	}
	o.keys = append(o.keys, key)
	o.vals = append(o.vals, v)
}

// Number is a JSON number token.
type Number string

// Parse reads exactly one JSON value into *Object, []any, string, Number,
// bool and nil. Duplicate member names are rejected: serde_json would keep
// only the last value, so what was hashed could differ from what was read.
func Parse(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, fmt.Errorf("serdejson: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("serdejson: trailing data after JSON value")
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := &Object{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key := kt.(string)
				if _, dup := obj.Get(key); dup {
					return nil, fmt.Errorf("duplicate member name %q", key)
				}
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				obj.keys = append(obj.keys, key)
				obj.vals = append(obj.vals, v)
			}
			_, err := dec.Token() // '}'
			return obj, err
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := parseValue(dec)
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
		return Number(t), nil
	default: // string, bool, nil
		return t, nil
	}
}

// Marshal writes v compactly, as serde_json writes the value it would parse
// from v.
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := write(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func write(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case *Object:
		b.WriteByte('{')
		for i, k := range t.keys {
			if i > 0 {
				b.WriteByte(',')
			}
			canon.WriteString(b, k)
			b.WriteByte(':')
			if err := write(b, t.vals[i]); err != nil {
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
		canon.WriteString(b, t)
	case Number:
		s, err := number(string(t))
		if err != nil {
			return err
		}
		b.WriteString(s)
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case nil:
		b.WriteString("null")
	default:
		return fmt.Errorf("serdejson: unsupported value of type %T", v)
	}
	return nil
}

// number writes a number token as serde_json writes the value it parses
// from it. An integer token that fits is kept as an integer, except "-0",
// which serde_json reads as the float -0.0. Anything else is a float, parsed
// exactly (float_roundtrip) and written by FormatFloat.
func number(tok string) (string, error) {
	if !strings.ContainsAny(tok, ".eE") {
		if digits, neg := strings.CutPrefix(tok, "-"); neg {
			if sig, err := strconv.ParseUint(digits, 10, 64); err == nil {
				if n := -int64(sig); n < 0 { // wraps like serde_json's i64 negation
					return strconv.FormatInt(n, 10), nil
				}
			}
		} else if sig, err := strconv.ParseUint(digits, 10, 64); err == nil {
			return strconv.FormatUint(sig, 10), nil
		}
	}
	f, err := strconv.ParseFloat(tok, 64)
	if err != nil || math.IsInf(f, 0) {
		return "", fmt.Errorf("serdejson: number %s is out of range", tok)
	}
	return FormatFloat(f), nil
}

// FormatFloat writes a finite float as serde_json does (its zmij formatter):
// the shortest digits that round-trip, in plain notation for decimal
// exponents -5 to 15 and scientific notation otherwise, always with a
// decimal point or an exponent: 1.0, 0.001, 1e-7, 1.5e+16.
func FormatFloat(f float64) string {
	var b strings.Builder
	if math.Signbit(f) {
		b.WriteByte('-')
		f = -f
	}
	if f == 0 {
		b.WriteString("0.0")
		return b.String()
	}
	mant, exp, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	digits := strings.Replace(mant, ".", "", 1)
	e, _ := strconv.Atoi(exp)
	n := len(digits)
	switch {
	case e >= -5 && e <= 15 && n-1 <= e: // 1234e7 -> 12340000000.0
		b.WriteString(digits)
		b.WriteString(strings.Repeat("0", e+1-n))
		b.WriteString(".0")
	case e >= 0 && e <= 15: // 1234e-2 -> 12.34
		b.WriteString(digits[:e+1])
		b.WriteByte('.')
		b.WriteString(digits[e+1:])
	case e >= -5 && e < 0: // 1234e-6 -> 0.001234
		b.WriteString("0.")
		b.WriteString(strings.Repeat("0", -e-1))
		b.WriteString(digits)
	default: // 1234e30 -> 1.234e+33
		b.WriteByte(digits[0])
		if n > 1 {
			b.WriteByte('.')
			b.WriteString(digits[1:])
		}
		b.WriteByte('e')
		if e >= 0 {
			b.WriteByte('+')
		} else {
			b.WriteByte('-')
			e = -e
		}
		b.WriteString(strconv.Itoa(e))
	}
	return b.String()
}
