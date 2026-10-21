package canon

import "testing"

func TestCanonicalize(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{ "b": 1, "a": [ {"y": null, "x": true} ] }`, `{"a":[{"x":true,"y":null}],"b":1}`},
		{`{"big": 1800000000000, "s": "<a&b>"}`, `{"big":1800000000000,"s":"<a&b>"}`},
	}
	for _, c := range cases {
		got, err := Canonicalize([]byte(c.in))
		if err != nil || string(got) != c.want {
			t.Errorf("Canonicalize(%s) = %s, %v; want %s", c.in, got, err, c.want)
		}
	}
}

// Each of these could make the parsed document differ from the signed
// canonical bytes, or from another verifier's reading of it.
func TestDecodeRejectsAmbiguousDocuments(t *testing.T) {
	for _, in := range []string{
		`{"a":1,"a":2}`,           // duplicate member, last-wins vs first-wins
		`{"a":{"b":1,"b":1}}`,     // duplicate member, nested
		`{"a":1.0}`,               // non-integer number
		`{"a":1e3}`,               // exponent form
		`{"a":-0}`,                // negative zero
		`{"é":1}`,                 // non-ASCII member name
		`[{"x":1},{"x":1,"x":2}]`, // duplicate inside an array
	} {
		if _, err := Decode([]byte(in)); err == nil {
			t.Errorf("Decode(%s) accepted", in)
		}
	}
	if _, err := Decode([]byte(`{"a":-12,"b":[true,null,"é"]}`)); err != nil {
		t.Errorf("valid document rejected: %v", err)
	}
}

func TestDecodeRejectsTrailingData(t *testing.T) {
	for _, in := range []string{`{"a":1} {"b":2}`, `{"a":1}x`} {
		if _, err := Decode([]byte(in)); err == nil {
			t.Errorf("Decode(%q) accepted trailing data", in)
		}
	}
	if _, err := Decode([]byte("{\"a\":1}\n")); err != nil {
		t.Errorf("trailing whitespace rejected: %v", err)
	}
}
