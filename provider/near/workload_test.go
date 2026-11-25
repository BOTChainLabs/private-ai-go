package near

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/BOTChainLabs/private-ai-go/internal/tdx"
)

// NEAR's gateway moved to dstack-0.5.12 (seen 2026-11-12): its OS build is
// accepted, as the one before it, and a build that is neither still is not.
func TestProductionWorkloadGatewayOnDstack0512(t *testing.T) {
	m := func(o tdx.OSMeasurement) tdx.Measurements {
		b := func(s string) []byte { v, _ := hex.DecodeString(s); return v }
		return tdx.Measurements{MRTD: b(o.MRTD), RTMR0: b(o.RTMR0), RTMR1: b(o.RTMR1), RTMR2: b(o.RTMR2)}
	}
	gw0512 := tdx.OSMeasurement{
		MRTD:  "7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173",
		RTMR0: "d090162bff4b1d1dc74dc59dc548838efc4b811b173da8536efa8e2a9c045da70ee092301293ad90afebee448bcd0211",
		RTMR1: "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec",
		RTMR2: "764489f277a8540189761e72b4238ba36d4d647e11bd958d8ab5522af2a4867b0ff63e06b0c4967f1857236244040a5d",
	}
	w := ProductionWorkload()
	if err := tdx.CheckOS(m(gw0512), w.OS); err != nil {
		t.Fatalf("the gateway on dstack-0.5.12 is refused: %v", err)
	}
	if err := tdx.CheckOS(m(w.OS[0]), w.OS); err != nil {
		t.Fatalf("the gateway's earlier build is refused: %v", err)
	}
	other := gw0512
	other.RTMR2 = strings.Repeat("00", 48)
	if err := tdx.CheckOS(m(other), w.OS); err == nil {
		t.Fatal("an unknown OS build is accepted")
	}
}
