package tdx

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// eventLog measures name/payload events into RTMR3 as dstack does. With
// withDigests false the digest fields are left empty, as NEAR's logs are.
func eventLog(t *testing.T, withDigests bool, events ...[2]string) ([]byte, []byte) {
	t.Helper()
	rtmr := make([]byte, 48)
	var log []map[string]any
	for _, e := range events {
		payload, _ := hex.DecodeString(e[1])
		h := sha512.New384()
		binary.Write(h, binary.LittleEndian, uint32(DstackEvent))
		h.Write([]byte(":" + e[0] + ":"))
		h.Write(payload)
		d := h.Sum(nil)
		ext := sha512.New384()
		ext.Write(rtmr)
		ext.Write(d)
		rtmr = ext.Sum(nil)
		digest := ""
		if withDigests {
			digest = hex.EncodeToString(d)
		}
		log = append(log, map[string]any{"imr": 3, "event_type": DstackEvent, "digest": digest, "event": e[0], "event_payload": e[1]})
	}
	b, _ := json.Marshal(log)
	return b, rtmr
}

var sample = [][2]string{{"app-id", "a1"}, {"compose-hash", "c0ffee"}, {"key-provider", "6b6d73"}, {"mr-kms", "55"}, {"system-ready", ""}}

func TestReplayRTMR3(t *testing.T) {
	for _, withDigests := range []bool{true, false} {
		log, rtmr := eventLog(t, withDigests, sample...)
		events, err := ReplayRTMR3(log, rtmr)
		if err != nil {
			t.Fatalf("digests=%v: %v", withDigests, err)
		}
		if events["app-id"] != "a1" || events["compose-hash"] != "c0ffee" {
			t.Fatalf("events %v", events)
		}
		// A log embedded as a JSON string, as some reports serve it.
		quoted, _ := json.Marshal(string(log))
		if _, err := ReplayRTMR3(quoted, rtmr); err != nil {
			t.Fatalf("JSON-string log: %v", err)
		}
	}
}

func TestReplayRTMR3BindsPayloads(t *testing.T) {
	for _, withDigests := range []bool{true, false} {
		log, rtmr := eventLog(t, withDigests, sample...)
		swapped := bytes.Replace(log, []byte(`"event_payload":"a1"`), []byte(`"event_payload":"a2"`), 1)
		if _, err := ReplayRTMR3(swapped, rtmr); err == nil {
			t.Fatalf("digests=%v: swapped payload accepted", withDigests)
		}
	}
}

func TestReplayRTMR3Rejects(t *testing.T) {
	dup, rtmr := eventLog(t, true, append(sample, [2]string{"app-id", "a1"})...)
	if _, err := ReplayRTMR3(dup, rtmr); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate app-id: %v", err)
	}
	// Repeated events that are not read as identity are fine.
	rep, rtmr := eventLog(t, true, append(sample, [2]string{"nearai-replica-report-key-v1", "01"}, [2]string{"nearai-replica-report-key-v1", "02"})...)
	if _, err := ReplayRTMR3(rep, rtmr); err != nil {
		t.Fatalf("repeated non-identity event: %v", err)
	}
	log, _ := eventLog(t, true, sample...)
	if _, err := ReplayRTMR3(log, make([]byte, 48)); err == nil {
		t.Fatal("wrong RTMR3 accepted")
	}
	other := bytes.Replace(log, []byte(`"event_type":134217729`), []byte(`"event_type":1`), 1)
	if _, err := ReplayRTMR3(other, make([]byte, 48)); err == nil {
		t.Fatal("non-dstack RTMR3 event accepted")
	}
}

// quote builds a minimal TDX quote of the given version with recognizable
// measurement bytes.
func quote(version uint16) []byte {
	header := make([]byte, 48)
	binary.LittleEndian.PutUint16(header[0:2], version)
	binary.LittleEndian.PutUint32(header[4:8], 0x81)
	body := make([]byte, 584)
	for off, b := range map[int]byte{136: 0x11, 184: 0xcc, 328: 0x20, 376: 0x21, 424: 0x22, 472: 0x23, 520: 0xdd} {
		n := 48
		if off == 520 {
			n = 64
		}
		copy(body[off:], bytes.Repeat([]byte{b}, n))
	}
	if version == 5 {
		header = append(header, 3, 0, 0x48, 2, 0, 0) // body type and size
	}
	return append(header, body...)
}

func TestParseQuote(t *testing.T) {
	for _, v := range []uint16{4, 5} {
		m, err := ParseQuote(quote(v))
		if err != nil {
			t.Fatalf("v%d: %v", v, err)
		}
		if m.MRTD[0] != 0x11 || m.MRConfigID[0] != 0xcc || m.RTMR1[0] != 0x21 || m.RTMR3[47] != 0x23 || len(m.ReportData) != 64 || m.ReportData[63] != 0xdd {
			t.Fatalf("v%d: %+v", v, m)
		}
	}
	bad := quote(4)
	bad[4] = 0x00 // SGX, not TDX
	if _, err := ParseQuote(bad); err == nil {
		t.Fatal("non-TDX quote accepted")
	}
	if _, err := ParseQuote(quote(3)); err == nil {
		t.Fatal("unsupported version accepted")
	}
	if _, err := ParseQuote(quote(4)[:300]); err == nil {
		t.Fatal("truncated quote accepted")
	}
}

func TestCheckOSAndApp(t *testing.T) {
	m, _ := ParseQuote(quote(4))
	os := OSOf(m)
	if err := CheckOS(m, []OSMeasurement{os}); err != nil {
		t.Fatal(err)
	}
	other := os
	other.RTMR0 = strings.Repeat("00", 48)
	if err := CheckOS(m, []OSMeasurement{other}); err == nil || !strings.Contains(err.Error(), os.RTMR0) {
		t.Fatalf("other OS: %v (want observed values in the error)", err)
	}

	events := map[string]string{"app-id": "a1", "key-provider": "6b6d73", "mr-kms": "55"}
	app := App{AppIDs: []string{"A1"}, KeyProviders: []string{"6b6d73"}, KMSMeasurements: []string{"55"}}
	if err := app.Check(events); err != nil {
		t.Fatal(err)
	}
	if err := (App{AppIDs: []string{"b2"}}).Check(events); err == nil {
		t.Fatal("other app accepted")
	}
	if err := (App{KMSMeasurements: []string{"55"}}).Check(map[string]string{}); err == nil {
		t.Fatal("missing mr-kms event accepted")
	}
}
