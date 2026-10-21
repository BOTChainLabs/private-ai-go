// Package tdx reads Intel TDX measurements and dstack event logs, shared by
// the providers to decide which code an attested VM runs.
//
// Nothing here verifies a quote's signature: callers use these functions only
// on quotes a DCAP verifier has accepted.
package tdx

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Measurements are the TD report fields of a TDX quote.
type Measurements struct {
	MRTD       []byte
	MRConfigID []byte
	RTMR0      []byte
	RTMR1      []byte
	RTMR2      []byte
	RTMR3      []byte
	ReportData []byte
}

// ParseQuote reads the TD report of a version 4 or 5 TDX quote.
func ParseQuote(q []byte) (Measurements, error) {
	const headerLen, td10Len = 48, 584
	if len(q) < headerLen {
		return Measurements{}, errors.New("quote too short")
	}
	if teeType := binary.LittleEndian.Uint32(q[4:8]); teeType != 0x81 {
		return Measurements{}, fmt.Errorf("not a TDX quote (tee type %#x)", teeType)
	}
	var body []byte
	switch v := binary.LittleEndian.Uint16(q[0:2]); v {
	case 4:
		body = q[headerLen:]
	case 5: // a body type and size precede the report; TD15 extends TD10
		if len(q) < headerLen+6 {
			return Measurements{}, errors.New("quote too short")
		}
		body = q[headerLen+6:]
	default:
		return Measurements{}, fmt.Errorf("unsupported quote version %d", v)
	}
	if len(body) < td10Len {
		return Measurements{}, errors.New("quote too short for a TD report")
	}
	field := func(off, n int) []byte { return bytes.Clone(body[off : off+n]) }
	return Measurements{
		MRTD:       field(136, 48),
		MRConfigID: field(184, 48),
		RTMR0:      field(328, 48),
		RTMR1:      field(376, 48),
		RTMR2:      field(424, 48),
		RTMR3:      field(472, 48),
		ReportData: field(520, 64),
	}, nil
}

// ParseHexQuote is ParseQuote for a hex-encoded quote.
func ParseHexQuote(hexQuote string) (Measurements, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(hexQuote, "0x"))
	if err != nil {
		return Measurements{}, fmt.Errorf("decode quote: %w", err)
	}
	return ParseQuote(raw)
}

// OSMeasurement identifies one dstack OS build by the measurements the guest
// cannot change: MRTD (firmware) and RTMR0-2 (firmware configuration,
// kernel, command line and initrd). Values are lowercase hex.
type OSMeasurement struct {
	MRTD, RTMR0, RTMR1, RTMR2 string
}

// OSOf returns the OS build a quote's measurements describe.
func OSOf(m Measurements) OSMeasurement {
	return OSMeasurement{
		MRTD:  hex.EncodeToString(m.MRTD),
		RTMR0: hex.EncodeToString(m.RTMR0),
		RTMR1: hex.EncodeToString(m.RTMR1),
		RTMR2: hex.EncodeToString(m.RTMR2),
	}
}

// CheckOS requires m to be one of the allowed OS builds. An empty list
// allows any build. The error carries the observed values, so a new build is
// easy to recognize and add.
func CheckOS(m Measurements, allowed []OSMeasurement) error {
	if len(allowed) == 0 {
		return nil
	}
	got := OSOf(m)
	if slices.ContainsFunc(allowed, func(a OSMeasurement) bool {
		return strings.EqualFold(a.MRTD, got.MRTD) && strings.EqualFold(a.RTMR0, got.RTMR0) &&
			strings.EqualFold(a.RTMR1, got.RTMR1) && strings.EqualFold(a.RTMR2, got.RTMR2)
	}) {
		return nil
	}
	return fmt.Errorf("unknown OS build: MRTD %s RTMR0 %s RTMR1 %s RTMR2 %s", got.MRTD, got.RTMR0, got.RTMR1, got.RTMR2)
}

// DstackEvent is the event type of the runtime events dstack measures into
// RTMR3 (app-id, compose-hash, key-provider, ...).
const DstackEvent = 0x08000001

type event struct {
	IMR          int    `json:"imr"`
	EventType    uint32 `json:"event_type"`
	Digest       string `json:"digest"`
	Event        string `json:"event"`
	EventPayload string `json:"event_payload"`
}

// identityEvents are read from the log, so each must appear at most once.
var identityEvents = []string{"app-id", "compose-hash", "key-provider", "mr-kms", "os-image-hash"}

// ReplayRTMR3 recomputes each dstack event's digest from its type, name and
// payload, replays the computed digests, checks the result against rtmr3 and
// returns the payloads by event name. Replaying computed digests is what
// binds the payloads: the log's own digest fields would let a payload be
// swapped without changing RTMR3. eventLog may be a JSON array or a JSON
// string holding one.
func ReplayRTMR3(eventLog []byte, rtmr3 []byte) (map[string]string, error) {
	var encoded string
	if json.Unmarshal(eventLog, &encoded) == nil {
		eventLog = []byte(encoded)
	}
	var events []event
	if err := json.Unmarshal(eventLog, &events); err != nil {
		return nil, fmt.Errorf("parse event log: %w", err)
	}
	rtmr := make([]byte, 48)
	payloads := map[string]string{}
	for _, e := range events {
		if e.IMR != 3 {
			continue
		}
		if e.EventType != DstackEvent {
			return nil, fmt.Errorf("unexpected RTMR3 event type %#x for %q", e.EventType, e.Event)
		}
		payload, err := hex.DecodeString(e.EventPayload)
		if err != nil {
			return nil, fmt.Errorf("RTMR3 event %q: bad payload", e.Event)
		}
		h := sha512.New384()
		binary.Write(h, binary.LittleEndian, e.EventType)
		h.Write([]byte(":" + e.Event + ":"))
		h.Write(payload)
		digest := h.Sum(nil)
		// The computed digest is what gets replayed, so the payload is bound
		// either way. A log may omit the digest (NEAR's does); one it states
		// must agree.
		if e.Digest != "" && !strings.EqualFold(hex.EncodeToString(digest), e.Digest) {
			return nil, fmt.Errorf("RTMR3 event %q: digest does not match its payload", e.Event)
		}
		ext := sha512.New384()
		ext.Write(rtmr)
		ext.Write(digest)
		rtmr = ext.Sum(nil)

		if slices.Contains(identityEvents, e.Event) {
			if _, dup := payloads[e.Event]; dup {
				return nil, fmt.Errorf("duplicate RTMR3 event %q", e.Event)
			}
		}
		payloads[e.Event] = strings.ToLower(e.EventPayload)
	}
	if !bytes.Equal(rtmr, rtmr3) {
		return nil, errors.New("replayed RTMR3 does not match the quote")
	}
	return payloads, nil
}

// App is the dstack application identity read from RTMR3: the app, and the
// KMS that released its keys. The KMS releases keys only to compose versions
// authorized for the app, so pinning these accepts the vendor's releases
// without tracking compose hashes.
type App struct {
	AppIDs          []string
	KeyProviders    []string
	KMSMeasurements []string
}

// Check requires the replayed events to carry an allowed app, key provider
// and KMS. A field left empty is not checked.
func (a App) Check(events map[string]string) error {
	for _, c := range []struct {
		event   string
		allowed []string
	}{
		{"app-id", a.AppIDs},
		{"key-provider", a.KeyProviders},
		{"mr-kms", a.KMSMeasurements},
	} {
		if len(c.allowed) == 0 {
			continue
		}
		got, ok := events[c.event]
		if !ok {
			return fmt.Errorf("event log has no %s event", c.event)
		}
		if !slices.ContainsFunc(c.allowed, func(v string) bool { return strings.EqualFold(v, got) }) {
			return fmt.Errorf("unexpected %s %s", c.event, got)
		}
	}
	return nil
}
