package serdejson

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const vectorsFile = "testdata/serde_vectors.json"

// vector is one document and what serde_json writes after parsing it, as
// recorded by tools/serdecheck.
type vector struct {
	In  string `json:"in"`
	Out string `json:"out"`
}

// TestSerdeVectors checks Marshal against serde_json's own output for the
// recorded corpus, and that the output is a fixed point.
func TestSerdeVectors(t *testing.T) {
	b, err := os.ReadFile(vectorsFile)
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 1000 {
		t.Fatalf("only %d vectors", len(vs))
	}
	for _, v := range vs {
		checkVector(t, v)
	}
}

func checkVector(t *testing.T, v vector) {
	t.Helper()
	doc, err := Parse([]byte(v.In))
	if err != nil {
		t.Errorf("parse %s: %v", v.In, err)
		return
	}
	got, err := Marshal(doc)
	if strings.HasPrefix(v.Out, "ERR ") {
		if err == nil {
			t.Errorf("%s: serde_json rejects it (%s), Marshal wrote %s", v.In, v.Out, got)
		}
		return
	}
	if err != nil || string(got) != v.Out {
		t.Errorf("%s: Marshal wrote %s (%v), serde_json %s", v.In, got, err, v.Out)
		return
	}
	again, _ := Parse(got)
	if fixed, _ := Marshal(again); string(fixed) != v.Out {
		t.Errorf("%s: not a fixed point: %s", v.Out, fixed)
	}
}

func TestFormatFloat(t *testing.T) {
	for f, want := range map[float64]string{
		0: "0.0", math.Copysign(0, -1): "-0.0", 1: "1.0", -1.5: "-1.5", 0.7: "0.7",
		100: "100.0", 1e15: "1000000000000000.0", 1e16: "1e+16", 1.5e16: "1.5e+16",
		1e-5: "0.00001", 1.25e-5: "0.0000125", 1e-6: "1e-6", 1.5e-7: "1.5e-7",
		math.Nextafter(0.3, 1): "0.30000000000000004", 1e21: "1e+21", 5e-324: "5e-324",
		math.MaxFloat64: "1.7976931348623157e+308",
	} {
		if got := FormatFloat(f); got != want {
			t.Errorf("FormatFloat(%v) = %s, want %s", f, got, want)
		}
	}
}

func TestNumbers(t *testing.T) {
	for in, want := range map[string]string{
		"0": "0", "-0": "-0.0", "512": "512", "-7": "-7", "0.70": "0.7", "1E5": "100000.0",
		"18446744073709551615": "18446744073709551615", "18446744073709551616": "1.8446744073709552e+19",
		"-9223372036854775808": "-9223372036854775808", "-9223372036854775809": "-9.223372036854776e+18",
		"1e-400": "0.0", "-1e-400": "-0.0",
	} {
		got, err := number(in)
		if err != nil || got != want {
			t.Errorf("number(%s) = %s, %v; want %s", in, got, err, want)
		}
	}
	if _, err := number("1e400"); err == nil {
		t.Error("1e400 accepted; serde_json rejects it as out of range")
	}
}

func TestOrderAndEscaping(t *testing.T) {
	in := `{"b":1,"a":[true,null,{"z":"< \n\u0001\u007f"}],"c":2.50}`
	doc, err := Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := Marshal(doc)
	want := "{\"b\":1,\"a\":[true,null,{\"z\":\"< \\n\\u0001\x7f\"}],\"c\":2.5}"
	if string(got) != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	o := doc.(*Object)
	o.Set("b", "x")
	o.Set("d", Number("3"))
	if got, _ := Marshal(o); !strings.HasPrefix(string(got), `{"b":"x","a":`) || !strings.HasSuffix(string(got), `"c":2.5,"d":3}`) {
		t.Fatalf("Set: %s", got)
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{`{"a":1,"a":2}`, `{"a":1} {}`, `{"a":`, ``} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
}

// TestCrossCheckSerde runs a large random corpus through serde_json itself.
// Build tools/serdecheck, then:
//
//	SERDECHECK=<path to serdecheck> go test ./internal/serdejson -run CrossCheck -v
//
// SERDECHECK_N sets the number of random floats (default 200000), and
// SERDECHECK_WRITE=1 records a smaller corpus as testdata/serde_vectors.json.
func TestCrossCheckSerde(t *testing.T) {
	bin := os.Getenv("SERDECHECK")
	if bin == "" {
		t.Skip("set SERDECHECK to a tools/serdecheck binary")
	}
	n := 200_000
	if s := os.Getenv("SERDECHECK_N"); s != "" {
		n, _ = strconv.Atoi(s)
	}
	write := os.Getenv("SERDECHECK_WRITE") != ""
	if write {
		n = 600
	}
	inputs := corpus(n)
	outputs := runSerde(t, bin, inputs)
	var vs []vector
	for i, in := range inputs {
		v := vector{In: in, Out: outputs[i]}
		checkVector(t, v)
		vs = append(vs, v)
	}
	t.Logf("%d documents compared with serde_json", len(vs))
	if write && !t.Failed() {
		b, _ := json.MarshalIndent(vs, "", " ")
		if err := os.WriteFile(vectorsFile, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func runSerde(t *testing.T, bin string, inputs []string) []string {
	t.Helper()
	cmd := exec.Command(filepath.Clean(bin))
	cmd.Stdin = strings.NewReader(strings.Join(inputs, "\n") + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("serdecheck: %v", err)
	}
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) != len(inputs) {
		t.Fatalf("serdecheck wrote %d lines for %d inputs", len(lines), len(inputs))
	}
	return lines
}

// corpus is edge cases plus n random floats, each written both as
// encoding/json writes it and as FormatFloat does.
func corpus(n int) []string {
	r := rand.New(rand.NewPCG(1, 2))
	floats := []float64{
		0, math.Copysign(0, -1), 1, -1, 0.1, 0.2, 0.7, 0.95, math.Nextafter(0.3, 1), 1.0 / 3, 2.0 / 3,
		1e-5, 1e-6, 1.5e-6, 9.999e-6, 1e15, 999999999999999.9, 1e16, 1.5e16, 1e21, 1e22, 1e23, 1e300,
		5e-324, 2.2250738585072014e-308, 2.225073858507201e-308, math.MaxFloat64, math.SmallestNonzeroFloat64,
		1 << 53, 1<<53 + 2, 1 << 63, 1 << 64, 123456789012345680, 9007199254740993,
	}
	for range n {
		var f float64
		switch r.IntN(3) {
		case 0: // any bit pattern
			f = math.Float64frombits(r.Uint64())
		case 1: // a short decimal, as people write parameters
			f, _ = strconv.ParseFloat(fmt.Sprintf("%de%d", r.IntN(100000), r.IntN(50)-25), 64)
		default: // a value near a power of ten
			f = math.Pow(10, float64(r.IntN(60)-30)) * (1 + (r.Float64()-0.5)*1e-12)
		}
		if math.IsInf(f, 0) || math.IsNaN(f) {
			continue
		}
		floats = append(floats, f)
	}
	var docs []string
	for _, f := range floats {
		goJSON, _ := json.Marshal(f)
		docs = append(docs, string(goJSON), FormatFloat(f))
	}
	docs = append(docs,
		"0", "-0", "1", "-1", "18446744073709551615", "18446744073709551616", "-9223372036854775808",
		"-9223372036854775809", "9223372036854775807", "123456789012345678901234567890",
		"-123456789012345678901234567890", "1E5", "1e+5", "0.000", "100.000", "1.0e0", "-0.0", "-0e0",
		"0e-5", "1e400", "-1e400", "1e-400",
	)
	var all strings.Builder
	for c := range 0x80 {
		all.WriteRune(rune(c))
	}
	for _, s := range []string{
		all.String(), "  ", "<>&'", "�", "日本語", "emoji 😀", "\\\"/", "",
		"line\nbreak\ttab\r\b\f", strings.Repeat("a", 1000),
	} {
		b, _ := json.Marshal(s)
		docs = append(docs, string(b))
	}
	docs = append(docs,
		`{"b":1,"a":[1,2,{"z":null,"y":true}],"model":"z-ai/glm-5.3"}`,
		`{"messages":[{"role":"user","content":"hi"}],"temperature":0.7,"max_tokens":512,"stream":false}`,
		`[]`, `{}`, `[[[]]]`, `{"a":{"b":{"c":[1.5,"x",false]}}}`,
	)
	return docs
}
