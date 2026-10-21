package near

import "github.com/BOTChainLabs/private-ai-go/internal/tdx"

// Workload is the code NEAR's gateway and model VMs must be running. NEAR's
// SDK proves a genuine TDX VM with a measured compose; the workload pins
// which VM:
//
//   - OS: the dstack OS builds, by MRTD and RTMR0-2 (not changeable by the
//     guest).
//   - Gateway and Model: NEAR's dstack apps and the KMS that released their
//     keys, read from the RTMR3 event log. The KMS releases keys only to
//     compose versions authorized for the app, so NEAR's releases (the model
//     compose differs between replicas) are accepted without listing
//     compose hashes.
//
// A field left empty is not checked.
type Workload struct {
	OS      []tdx.OSMeasurement
	Gateway tdx.App
	Model   tdx.App
}

// nearKMS is the key-provider event of NEAR's dstack KMS:
// {"name":"kms","id":"<KMS public key, DER>"}.
const nearKMS = "7b226e616d65223a226b6d73222c226964223a223330353933303133303630373261383634386365336430323031303630383261383634386365336430333031303730333432303030343339346161656432633734356536613435376362383335663766343734323366353766663365616437316239326162666636626463313464393035623331396632653133393631623432633530373430646165343439386439633531646437613265323237363630633965356335303430383363646130366236633131363832227d"

// ProductionWorkload is NEAR AI Cloud's gateway and the z-ai/glm-5.3-flash
// model deployment, as attested on 2026-10-21 and stable across repeated
// samples (model replicas run differing compose versions). Other models run
// as other apps: calling one fails with its observed app ID, which is then
// added to Model.AppIDs. A dstack OS upgrade fails the same way.
func ProductionWorkload() Workload {
	return Workload{
		OS: []tdx.OSMeasurement{
			{ // gateway
				MRTD:  "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
				RTMR0: "fb14dc139f33d6fcf474bc8332cac001259fb31cfbcb6b34d4ceeb552a2c4466884a0cbde45ad98a05c5c060c23ad65a",
				RTMR1: "a7b523278d4f914ee8df0ec80cd1c3d498cbf1152b0c5eaf65bad9425072874a3fcf891e8b01713d3d9937e3e0d26c15",
				RTMR2: "24847f5c5a2360d030bc4f7b8577ce32e87c4d051452c937e91220cab69542daef83433947c492b9c201182fc9769bbe",
			},
			{ // model VMs
				MRTD:  "df4d77c857de652bd0fafa343a2026b51071ee03773d076d283abf1a7d36ff91ffa279ee4a617ac664f7e2a2c8d5891b",
				RTMR0: "bc122d143ab768565ba5c3774ff5f03a63c89a4df7c1f5ea38d3bd173409d14f8cbdcc36d40e703cccb996a9d9687590",
				RTMR1: "ff61e68fa04516b1813d2d478397a97a58f9ccc402b6d96fb73f5e5104a4acf155913caec99a0c19afc16ae0f3a77726",
				RTMR2: "4d662c04766145dfe084fd014969b19c387afe9bb1d4f972c6968d28a7a8b4937c414603a2cf446105eddce67a86f9ce",
			},
		},
		Gateway: tdx.App{
			AppIDs:       []string{"f550fdfb4eb8ad787c1bcd423f091cbb4a4431ae"},
			KeyProviders: []string{nearKMS},
		},
		Model: tdx.App{
			AppIDs:          []string{"2c0a0c96cb6dbd659bf1446e2f3fce58172ff91b"}, // z-ai/glm-5.3-flash
			KeyProviders:    []string{nearKMS},
			KMSMeasurements: []string{"a1fc13604b253a3f664897dd486fd6dd0803242f92ff8e4f1c5cc12d1fb7e641"},
		},
	}
}
