package phala

import "github.com/BOTChainLabs/private-ai-go/internal/tdx"

// Workload is the code a Phala gateway must be running. A genuine Intel TDX
// quote alone proves only "some TDX VM"; the workload pins which one:
//
//   - OS: the dstack OS image, by its boot measurements (MRTD and RTMR0-2,
//     which the guest cannot change).
//   - AppIDs: Phala's gateway app, as measured into RTMR3 by that OS.
//   - KeyProviders: the app's keys come from Phala's dstack KMS, identified
//     by its root key. The KMS releases keys only to compose versions
//     authorized for the app by Phala's governance, so gateway releases are
//     accepted without tracking compose hashes here;
//     core.Policy.ComposeHashes can pin them additionally.
//   - KMSMeasurements: the KMS's own build (the mr-kms event). The KMS is
//     upgraded under the same root key, so ProductionWorkload leaves it
//     unpinned, as it does compose hashes.
//
// The values are lowercase hex. A field left empty is not checked.
type Workload struct {
	OS              []OSMeasurement
	AppIDs          []string
	KeyProviders    []string
	KMSMeasurements []string
}

// OSMeasurement is one accepted dstack OS build.
type OSMeasurement = tdx.OSMeasurement

// ProductionWorkload is Phala's production gateway behind
// inference.phala.com, as attested on 2026-10-18 and 2026-10-20. All values
// were identical across the gateway release between those dates. A dstack
// OS upgrade changes the OS measurements; verification then fails with the
// observed values in the error, and the new build is added here.
func ProductionWorkload() Workload {
	return Workload{
		OS: []OSMeasurement{{
			MRTD:  "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
			RTMR0: "46a83f6bbbeaa274aaf04861ef47d7e8898d4e699126b642f72f582e8d7f5349cb266a188bbabf619940d4fece06594b",
			RTMR1: "07e6f51aa763abfe75c3ddfbf4f425fe3f0ceff66d807a75e049303dce9addf68e7218729bd419638af63a370f65878c",
			RTMR2: "df67e467e60edc1737bcf8e682d48131bfb427f523226aa7f197a7608e9b3784783fa759ef5b28191fa12f9ddb36b858",
		}},
		AppIDs: []string{"fdb7a14e5a6675f752e2cb69c9067a98ca402918"},
		KeyProviders: []string{
			// {"name":"kms","id":"<Phala KMS public key, DER>"}
			"7b226e616d65223a226b6d73222c226964223a223330353933303133303630373261383634386365336430323031303630383261383634386365336430333031303730333432303030343838343465623432636364663863353266643466313734663336326663623962626431396334356664343866316564656332643866316361323335333665633161373430323162346365653631306330373466383239346434333162326237666565326333396535333333666461663061343532326434336662313539643966227d",
		},
	}
}
