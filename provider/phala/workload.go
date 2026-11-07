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

// cloudKeyProvider is Phala Cloud's KMS, {"name":"kms","id":"<its public
// key, DER>"}: the KMS of CVMs deployed on Phala Cloud, and of Phala's
// gateway until 2026-11-06.
const cloudKeyProvider = "7b226e616d65223a226b6d73222c226964223a223330353933303133303630373261383634386365336430323031303630383261383634386365336430333031303730333432303030343838343465623432636364663863353266643466313734663336326663623962626431396334356664343866316564656332643866316361323335333665633161373430323162346365653631306330373466383239346434333162326237666565326333396535333333666461663061343532326434336662313539643966227d"

// CloudKeyProviders are the KMS of CVMs deployed on Phala Cloud: the key
// providers a self-hosted gateway there is checked against unless its
// identity names others.
func CloudKeyProviders() []string { return []string{cloudKeyProvider} }

// ProductionWorkload is Phala's production gateway behind
// inference.phala.com, in both of the deployments it has had:
//
//   - until 2026-11-06 (attested 2026-10-18 and 2026-10-20): app fdb7a14e on
//     Phala Cloud's KMS, on dstack OS 0.5;
//   - since 2026-11-06 (attested 2026-11-06): app 89c51ab8, an app contract
//     on Base that lists the compose versions allowed to get keys, on the
//     dstack KMS whose root key is
//     02a335aea3df11d46ae0a373d3f26fbd1d208572ecc87e630e618dac693b7af721,
//     on dstack OS 0.5.12 (os_image_hash 8db40cb2), gateway commit e9b6ae8a.
//
// The old values are kept so a rollback still verifies. Any OS build, app and
// key provider listed here is accepted with any other. A dstack OS upgrade
// changes the OS measurements; verification then fails with the observed
// values in the error, and the new build is added here.
func ProductionWorkload() Workload {
	return Workload{
		OS: []OSMeasurement{{
			MRTD:  "f06dfda6dce1cf904d4e2bab1dc370634cf95cefa2ceb2de2eee127c9382698090d7a4a13e14c536ec6c9c3c8fa87077",
			RTMR0: "46a83f6bbbeaa274aaf04861ef47d7e8898d4e699126b642f72f582e8d7f5349cb266a188bbabf619940d4fece06594b",
			RTMR1: "07e6f51aa763abfe75c3ddfbf4f425fe3f0ceff66d807a75e049303dce9addf68e7218729bd419638af63a370f65878c",
			RTMR2: "df67e467e60edc1737bcf8e682d48131bfb427f523226aa7f197a7608e9b3784783fa759ef5b28191fa12f9ddb36b858",
		}, {
			MRTD:  "7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173",
			RTMR0: "d6118f0eeb30e9d9178d2b9106dddd002d979b6fa79bdec415051afae2021384c29a32d2f6454fa369617598378ffb5e",
			RTMR1: "4ae609807c765916a31d724786ed74bcb97e168a9d937b04936aeef2015c907eba5ac352c6bcd749c246fd62ffb659ec",
			RTMR2: "764489f277a8540189761e72b4238ba36d4d647e11bd958d8ab5522af2a4867b0ff63e06b0c4967f1857236244040a5d",
		}},
		AppIDs: []string{
			"fdb7a14e5a6675f752e2cb69c9067a98ca402918",
			"89c51ab856bee41efe78c40309a4deb277a02a0f",
		},
		KeyProviders: []string{
			cloudKeyProvider,
			// {"name":"kms","id":"<the Base dstack KMS's public key, DER>"}
			"7b226e616d65223a226b6d73222c226964223a223330353933303133303630373261383634386365336430323031303630383261383634386365336430333031303730333432303030343862663834663532393131303536343734633230376362353062346538303130643938346638393735656135376238663063386231373530323138316332383365393361363861393836346164313966363239353038636336393966313235626533383731656332653236616230353937653562636134653239623734323566227d",
		},
	}
}
