package privateai

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/BOTChainLabs/private-ai-go/provider/near"
	"github.com/BOTChainLabs/private-ai-go/provider/phala"
)

func newTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{
		Providers: map[ProviderID]ProviderConfig{Phala: {APIKey: "k"}},
		Models:    []ModelEntry{{Provider: Phala, Model: "z-ai/glm-5.3"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func errCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestModelAllowlist(t *testing.T) {
	_, err := newTestClient(t).Infer(context.Background(), InferRequest{
		Provider: Phala, Model: "openai/gpt-5", Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if errCode(err) != "MODEL_NOT_ALLOWED" {
		t.Fatalf("err = %v", err)
	}
}

func TestStreamChecksAllowlist(t *testing.T) {
	_, err := newTestClient(t).Stream(context.Background(), InferRequest{
		Provider: Phala, Model: "openai/gpt-5", Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if errCode(err) != "MODEL_NOT_ALLOWED" {
		t.Fatalf("err = %v", err)
	}
}

func TestEmptyMessagesRejected(t *testing.T) {
	_, err := newTestClient(t).Infer(context.Background(), InferRequest{Provider: Phala, Model: "z-ai/glm-5.3"})
	if errCode(err) != "INVALID_REQUEST" {
		t.Fatalf("err = %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	phala := map[ProviderID]ProviderConfig{Phala: {APIKey: "k"}}
	if _, err := New(Config{Providers: phala, Models: []ModelEntry{{Provider: Phala}}}); err == nil {
		t.Fatal("accepted a model without a name")
	}
	if _, err := New(Config{Providers: phala, Models: []ModelEntry{{Provider: Phala, Model: "m"}}, Timeout: -1}); err == nil {
		t.Fatal("accepted a negative timeout")
	}
	if _, err := New(Config{Providers: map[ProviderID]ProviderConfig{Phala: {APIKey: "k"}}}); err == nil {
		t.Fatal("accepted a config with no models")
	}
	if _, err := New(Config{
		Providers: map[ProviderID]ProviderConfig{Phala: {APIKey: "k"}},
		Models:    []ModelEntry{{Provider: NEAR, Model: "x"}},
	}); err == nil {
		t.Fatal("accepted a model for an unconfigured provider")
	}
}

var extraOS = OSMeasurement{MRTD: strings.Repeat("aa", 48), RTMR0: strings.Repeat("bb", 48), RTMR1: strings.Repeat("cc", 48), RTMR2: strings.Repeat("dd", 48)}

const extraApp = "1111111111111111111111111111111111111111"

func TestExtraIdentityExtendsBuiltIn(t *testing.T) {
	pc := ProviderConfig{ExtraOSBuilds: []OSMeasurement{extraOS}, ExtraAppIDs: []string{extraApp}}

	pw, nw := phala.ProductionWorkload(), near.ProductionWorkload()
	p := phalaOptions(pc, 0).Workload
	if !slices.Equal(p.OS, append(pw.OS, extraOS)) || !slices.Equal(p.AppIDs, append(pw.AppIDs, extraApp)) {
		t.Fatalf("phala workload %+v", p)
	}
	n := nearOptions(pc, 0).Workload
	if !slices.Equal(n.OS, append(nw.OS, extraOS)) || !slices.Equal(n.Model.AppIDs, append(nw.Model.AppIDs, extraApp)) {
		t.Fatalf("near workload %+v", n)
	}
	if !slices.Equal(n.Gateway.AppIDs, nw.Gateway.AppIDs) {
		t.Fatal("an extra app ID was accepted as NEAR's gateway")
	}
	// Phala's deployments keep their own KMS: the extras join each of them.
	if len(p.Deployments) != len(pw.Deployments) {
		t.Fatalf("deployments %+v", p.Deployments)
	}
	for i, d := range p.Deployments {
		b := pw.Deployments[i]
		if !slices.Equal(d.OS, append(b.OS, extraOS)) || !slices.Equal(d.AppIDs, append(b.AppIDs, extraApp)) || !slices.Equal(d.KeyProviders, b.KeyProviders) {
			t.Fatalf("deployment %d: %+v", i, d)
		}
	}
	// Without extras, the built-in identity is used unchanged.
	if w := phalaOptions(ProviderConfig{}, 0).Workload; !slices.Equal(w.OS, pw.OS) || !slices.Equal(w.Deployments[0].OS, pw.Deployments[0].OS) {
		t.Fatal("phala OS builds changed without extras")
	}
}

func TestExtraIdentityValidation(t *testing.T) {
	short := extraOS
	short.RTMR1 = "cc"
	cases := map[string]ProviderConfig{
		"short RTMR":     {APIKey: "k", ExtraOSBuilds: []OSMeasurement{short}},
		"missing MRTD":   {APIKey: "k", ExtraOSBuilds: []OSMeasurement{{RTMR0: extraOS.RTMR0, RTMR1: extraOS.RTMR1, RTMR2: extraOS.RTMR2}}},
		"non-hex app ID": {APIKey: "k", ExtraAppIDs: []string{strings.Repeat("zz", 20)}},
		"short app ID":   {APIKey: "k", ExtraAppIDs: []string{"2c0a0c96"}},
	}
	for name, pc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := New(Config{
				Providers: map[ProviderID]ProviderConfig{NEAR: pc},
				Models:    []ModelEntry{{Provider: NEAR, Model: "x"}},
			})
			if err == nil {
				t.Fatal("accepted a malformed identity value")
			}
		})
	}
	if _, err := New(Config{
		Providers: map[ProviderID]ProviderConfig{NEAR: {APIKey: "k", ExtraOSBuilds: []OSMeasurement{extraOS}, ExtraAppIDs: []string{extraApp}}},
		Models:    []ModelEntry{{Provider: NEAR, Model: "x"}},
	}); err != nil {
		t.Fatal(err)
	}
}

var testGateway = GatewayIdentity{AppIDs: []string{extraApp}, OS: []OSMeasurement{extraOS}, ComposeHashes: []string{strings.Repeat("ab", 32)}}

func TestGatewayUsesItsOwnIdentity(t *testing.T) {
	o, err := gatewayOptions(ProviderConfig{APIKey: "k", BaseURL: "https://gw.example", Identity: &testGateway, ExtraAppIDs: []string{strings.Repeat("22", 20)}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	w := o.Workload
	// The release is pinned, and TLS that ends outside the TEE is refused
	// unless the caller accepts it.
	if o.ID != Gateway || !o.E2EE || o.UnpinnedTLS || !slices.Equal(o.Policy.ComposeHashes, testGateway.ComposeHashes) {
		t.Fatalf("options %+v", o)
	}
	outside := testGateway
	outside.AllowTLSOutsideTEE = true
	if o, err := gatewayOptions(ProviderConfig{APIKey: "k", BaseURL: "https://gw.example", Identity: &outside}, 0); err != nil || !o.UnpinnedTLS {
		t.Fatalf("TLS outside the TEE: %+v, %v", o, err)
	}
	if !slices.Equal(w.OS, []OSMeasurement{extraOS}) || !slices.Equal(w.AppIDs, []string{extraApp, strings.Repeat("22", 20)}) {
		t.Fatalf("workload %+v", w)
	}
	// Phala's gateway apps are never accepted for someone else's gateway, and
	// the default key provider is Phala Cloud's KMS alone, not the KMS of
	// Phala's own gateway.
	for _, app := range phala.ProductionWorkload().AppIDs {
		if slices.Contains(w.AppIDs, app) {
			t.Fatalf("Phala's app %s accepted for a self-hosted gateway", app)
		}
	}
	if !slices.Equal(w.KeyProviders, phala.CloudKeyProviders()) || len(w.KeyProviders) != 1 {
		t.Fatalf("key providers %v", w.KeyProviders)
	}
}

func TestGatewayConfigValidation(t *testing.T) {
	noOS := GatewayIdentity{AppIDs: testGateway.AppIDs, ComposeHashes: testGateway.ComposeHashes}
	noCompose := GatewayIdentity{AppIDs: testGateway.AppIDs, OS: testGateway.OS}
	badCompose := testGateway
	badCompose.ComposeHashes = []string{"abcd"}
	badKMS := testGateway
	badKMS.KeyProviders = []string{"not hex"}
	cases := map[string]map[ProviderID]ProviderConfig{
		"no identity":       {Gateway: {APIKey: "k", BaseURL: "https://gw.example"}},
		"no base URL":       {Gateway: {APIKey: "k", Identity: &testGateway}},
		"http base URL":     {Gateway: {APIKey: "k", BaseURL: "http://gw.example", Identity: &testGateway}},
		"no OS":             {Gateway: {APIKey: "k", BaseURL: "https://gw.example", Identity: &noOS}},
		"no compose pin":    {Gateway: {APIKey: "k", BaseURL: "https://gw.example", Identity: &noCompose}},
		"bad compose pin":   {Gateway: {APIKey: "k", BaseURL: "https://gw.example", Identity: &badCompose}},
		"compose in Policy": {Gateway: {APIKey: "k", BaseURL: "https://gw.example", Identity: &testGateway, Policy: Policy{ComposeHashes: testGateway.ComposeHashes}}},
		"bad key provider":  {Gateway: {APIKey: "k", BaseURL: "https://gw.example", Identity: &badKMS}},
		"identity on Phala": {Phala: {APIKey: "k", Identity: &testGateway}},
	}
	for name, providers := range cases {
		t.Run(name, func(t *testing.T) {
			var models []ModelEntry
			for id := range providers {
				models = append(models, ModelEntry{Provider: id, Model: "m"})
			}
			if _, err := New(Config{Providers: providers, Models: models}); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	c, err := New(Config{
		Providers: map[ProviderID]ProviderConfig{Gateway: {APIKey: "k", BaseURL: "https://gw.example", Identity: &testGateway}},
		Models:    []ModelEntry{{Provider: Gateway, Model: "z-ai/glm-5.3"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestPhalaE2EEIsOptIn(t *testing.T) {
	if phalaOptions(ProviderConfig{}, 0).E2EE || !phalaOptions(ProviderConfig{E2EE: true}, 0).E2EE {
		t.Fatal("ProviderConfig.E2EE not passed to Phala")
	}
}
