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
	// Without extras, the built-in identity is used unchanged.
	if !slices.Equal(phalaOptions(ProviderConfig{}, 0).Workload.OS, pw.OS) {
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
