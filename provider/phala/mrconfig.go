package phala

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// mrConfigV1 is the MRCONFIGID dstack sets for an app without a key
// provider ID: version 1, then the compose hash.
func mrConfigV1(composeSum [32]byte) []byte {
	return append(append([]byte{0x01}, composeSum[:]...), make([]byte, 15)...)
}

// mrConfigV3 is the document whose hash dstack 0.6 puts in MRCONFIGID for
// an app with a key provider ID (dstack-types mr_config.rs, MrConfigV3).
// The members are in JCS order, and encoding/json writes them so: the
// values are hex strings, a kind name and a small integer.
type mrConfigV3 struct {
	AppID            string    `json:"app_id"`
	ComposeHash      string    `json:"compose_hash"`
	GPUPolicyHash    string    `json:"gpu_policy_hash,omitempty"`
	InitScriptHashes *[]string `json:"init_script_hashes,omitempty"`
	InstanceID       string    `json:"instance_id,omitempty"`
	KeyProvider      string    `json:"key_provider"`
	KeyProviderID    string    `json:"key_provider_id,omitempty"`
	Version          int       `json:"version"`
}

// mrConfigV3IDs returns the MRCONFIGIDs a launch of appCompose with the
// measured identity in events can have under version 3. The host does not
// publish the document, so it is rebuilt from the attested compose and
// RTMR3 events: any value other than the launched one changes the hash.
// A GPU launch also binds the GPU policy hash, and whether there were GPUs
// is not attested, so with a gpu-policy-hash event both forms are returned.
func mrConfigV3IDs(appCompose, composeHash string, events map[string]string) ([][]byte, error) {
	var c struct {
		ManifestVersion         json.RawMessage `json:"manifest_version"`
		InitScript              json.RawMessage `json:"init_script"`
		KeyProvider             string          `json:"key_provider"`
		KeyProviderID           string          `json:"key_provider_id"`
		KMSEnabled              bool            `json:"kms_enabled"`
		LocalKeyProviderEnabled bool            `json:"local_key_provider_enabled"`
	}
	if err := json.Unmarshal([]byte(appCompose), &c); err != nil {
		return nil, fmt.Errorf("parse app_compose: %w", err)
	}
	appID := events["app-id"]
	if len(appID) != 40 {
		return nil, fmt.Errorf("MRCONFIGID v3 needs a 20-byte app-id event, got %q", appID)
	}
	doc := mrConfigV3{
		AppID:         appID,
		ComposeHash:   composeHash,
		InstanceID:    events["instance-id"],
		KeyProvider:   c.KeyProvider,
		KeyProviderID: strings.ToLower(c.KeyProviderID),
		Version:       3,
	}
	if doc.KeyProvider == "" {
		switch {
		case c.KMSEnabled:
			doc.KeyProvider = "kms"
		case c.LocalKeyProviderEnabled:
			doc.KeyProvider = "local"
		default:
			doc.KeyProvider = "none"
		}
	}
	// Manifest v3 and later bind the init scripts, in order; an empty list
	// still says there are none.
	if v, _ := strconv.Atoi(strings.Trim(string(c.ManifestVersion), `"`)); v >= 3 {
		scripts, err := initScripts(c.InitScript)
		if err != nil {
			return nil, err
		}
		hashes := make([]string, len(scripts))
		for i, s := range scripts {
			sum := sha256.Sum256([]byte(s))
			hashes[i] = hex.EncodeToString(sum[:])
		}
		doc.InitScriptHashes = &hashes
	}
	ids := [][]byte{mrConfigV3ID(doc)}
	if gpu := events["gpu-policy-hash"]; gpu != "" {
		doc.GPUPolicyHash = gpu
		ids = append(ids, mrConfigV3ID(doc))
	}
	return ids, nil
}

// initScripts reads app_compose's init_script: absent, one script, or a
// list.
func initScripts(raw json.RawMessage) ([]string, error) {
	var one string
	var list []string
	switch {
	case len(raw) == 0 || string(raw) == "null":
		return nil, nil
	case json.Unmarshal(raw, &one) == nil:
		return []string{one}, nil
	case json.Unmarshal(raw, &list) == nil:
		return list, nil
	}
	return nil, fmt.Errorf("app_compose init_script is neither a string nor a list")
}

func mrConfigV3ID(doc mrConfigV3) []byte {
	b, _ := json.Marshal(doc) // a struct of strings and an int
	sum := sha256.Sum256(append([]byte("dstack-mr-config-v3:\x00"), b...))
	return append(append([]byte{0x03}, sum[:]...), make([]byte, 15)...)
}
