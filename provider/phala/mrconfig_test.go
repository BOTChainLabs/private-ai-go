package phala

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/BOTChainLabs/private-ai-go/core"
)

// The expected IDs were computed apart from this code, by a script that
// also reproduced the MRCONFIGID of a real dstack-0.6.1 CVM on Phala Cloud.
func TestMRConfigV3Document(t *testing.T) {
	kpid := strings.Repeat("33", 32)
	events := map[string]string{
		"app-id":          strings.Repeat("11", 20),
		"instance-id":     strings.Repeat("44", 20),
		"gpu-policy-hash": strings.Repeat("55", 32),
	}
	for _, c := range []struct {
		name, compose, plain, gpu string
	}{
		{"manifest 3 binds the init scripts",
			`{"manifest_version":"3","name":"gw","key_provider":"kms","key_provider_id":"` + kpid + `","init_script":["echo one","echo two"]}`,
			"030bdd21575fff0ce3ef9b8240ca136ded0da36dd24eac1dcd16e81b150f4e4b14000000000000000000000000000000",
			"034ed2e5e585e969acd5993ea2f22b48fe6455ab2094f17f62896e638723981dca000000000000000000000000000000"},
		{"manifest 2 does not; kms_enabled names the provider",
			`{"manifest_version":2,"name":"gw","kms_enabled":true,"key_provider_id":"` + kpid + `","init_script":"echo one"}`,
			"0390750dc89db6b449d6d7f9478d52bad0255711c43d797ab4bd4bb90cb9fb6ee3000000000000000000000000000000",
			"03a78c610dcd85e6a7b43b32d730ba37362741a5638e98a01d8b25d5427de6f713000000000000000000000000000000"},
	} {
		t.Run(c.name, func(t *testing.T) {
			sum := sha256.Sum256([]byte(c.compose))
			ids, err := mrConfigV3IDs(c.compose, hex.EncodeToString(sum[:]), events)
			if err != nil {
				t.Fatal(err)
			}
			if len(ids) != 2 || hex.EncodeToString(ids[0]) != c.plain || hex.EncodeToString(ids[1]) != c.gpu {
				t.Fatalf("ids %x", ids)
			}
		})
	}

	compose := `{"manifest_version":"3","key_provider":"kms","key_provider_id":"` + kpid + `"}`
	if _, err := mrConfigV3IDs(compose, strings.Repeat("00", 32), map[string]string{"app-id": "a1a1"}); err == nil {
		t.Error("a short app-id was accepted")
	}
	if _, err := mrConfigV3IDs(`{"manifest_version":"3","init_script":{}}`, strings.Repeat("00", 32), events); err == nil {
		t.Error("an init_script object was accepted")
	}
}

// newV3Gateway is a fake dstack 0.6 launch of an app with a key provider
// ID, whose MRCONFIGID is version 3, for app appID and instance instance.
func newV3Gateway(t *testing.T, appID, instance string) *fakeGateway {
	t.Helper()
	g := newFakeGateway(t)
	g.appCompose = `{"manifest_version":"3","key_provider":"kms","key_provider_id":"` + strings.Repeat("33", 32) + `","init_script":[]}`
	sum := sha256.Sum256([]byte(g.appCompose))
	compose := hex.EncodeToString(sum[:])
	g.eventLog, g.rtmr3 = dstackEventLog([][2]string{
		{"app-id", strings.Repeat("a1", 20)},
		{"compose-hash", compose},
		{"instance-id", strings.Repeat("44", 20)},
		{"mr-kms", fakeWorkload.KMSMeasurements[0]},
		{"key-provider", fakeWorkload.KeyProviders[0]},
	})
	ids, err := mrConfigV3IDs(g.appCompose, compose, map[string]string{"app-id": appID, "instance-id": instance})
	if err != nil {
		t.Fatal(err)
	}
	g.mrConfig = ids[0]
	return g
}

func TestMRConfigV3IsVerified(t *testing.T) {
	appID := strings.Repeat("a1", 20)
	w := fakeWorkload
	w.AppIDs = []string{appID}
	withWorkload := func(o *Options) { o.Workload = &w }

	res, err := newV3Gateway(t, appID, strings.Repeat("44", 20)).provider(t, withWorkload).Infer(context.Background(), testReq)
	if err != nil || res.Verification.Status != core.Verified {
		t.Fatalf("v3 launch: %v", err)
	}
	// Launched as another instance, or with no binding at all: refused.
	g := newV3Gateway(t, appID, strings.Repeat("45", 20))
	_, err = g.provider(t, withWorkload).Infer(context.Background(), testReq)
	assertCode(t, err, core.CodeAttestationFailed)
	if !strings.Contains(err.Error(), "MRCONFIGID v3") {
		t.Fatalf("other instance: %v", err)
	}
	g = newV3Gateway(t, appID, strings.Repeat("44", 20))
	g.mrConfig = make([]byte, 48)
	_, err = g.provider(t, withWorkload).Infer(context.Background(), testReq)
	assertCode(t, err, core.CodeAttestationFailed)
}
