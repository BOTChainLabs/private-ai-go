// Differential check against Phala's official TypeScript verifier.
//
// Runs @phala/aci-verifier over a captured attestation report and a set of
// receipt cases, and writes its verdicts to ts-result.json. The Go test
// TestCrossCheckWithOfficialVerifier then runs our implementation over the
// same bytes and requires identical results.
//
// Usage:
//   node crosscheck.mjs <path to @phala/aci-verifier/dist/index.js> <workdir>
//
// <workdir> must contain report.json and nonce.txt (the nonce the report was
// fetched with). See README.md in this directory.
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [verifierPath, workdir] = process.argv.slice(2);
if (!verifierPath || !workdir) {
  console.error("usage: node crosscheck.mjs <verifier dist/index.js> <workdir>");
  process.exit(2);
}
const aci = await import(pathToFileURL(verifierPath).href);

// --- attestation report -----------------------------------------------------
const report = JSON.parse(await readFile(join(workdir, "report.json"), "utf8"));
const nonce = (await readFile(join(workdir, "nonce.txt"), "utf8")).trim();

const keysetDigest = await aci.computeKeysetDigest(report.attestation.workload_keyset);
const reportData = await aci.computeReportData(keysetDigest, nonce);
const binding = await aci.verifyReportBinding(report, nonce);
const compose = await aci.verifyComposeMeasurement(report);
const quote = await aci.verifyQuote(report);

// --- receipts: ACI test vector plus mutations ---------------------------------
const vecKeyset = {
  e2ee_public_keys: [{ algo: "x25519-aes-256-gcm-hkdf-sha256", key_id: "e2ee-1", public_key: "5dfedd3b6bd47f6fa28ee15d969d5bb0ea53774d488bdaf9df1c6e0124b3ef22" }],
  not_after: 1800000000,
  receipt_signing_keys: [{ algo: "ed25519", key_id: "receipt-1", public_key: "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394" }],
  subject: "dstack-app://example-app",
  tls_public_keys: [{ domain: "api.example.com", spki_sha256: "c0".repeat(32) }],
};
const vecDigest = "sha256:53a5cd44b30dcc51999754c719f2628a041f174ecbf9662a6f8e898a10cd9371";
const vecRequest = '{"messages":[{"content":"hi","role":"user"}],"model":"demo-model"}';
const vecResponse = '{"choices":[],"id":"chatcmpl-123"}';
const vecReceipt = '{"api_version":"aci/1","chat_id":"chatcmpl-123","endpoint":"/v1/chat/completions","event_log":[{"body_hash":"sha256:94d809bf47380d8a2eab0eb6e126d4dda9364b0b4725cdf7ead52dd70b2aa87b","type":"request.received"},{"body_hash":"sha256:94d809bf47380d8a2eab0eb6e126d4dda9364b0b4725cdf7ead52dd70b2aa87b","type":"request.forwarded"},{"model_id":"demo-model","required":true,"result":"verified","session_id":"95ad1cb4dd25445808c2e9d116caf420b05703730b506395e8fc1ca6faeae28f","type":"upstream.verified"},{"body_hash":"sha256:dedfffe5b14d031b8e2c01996d021a15293cb7c63b56be7e4be9e89b6f0a5f61","type":"response.returned"}],"key_id":"receipt-1","method":"POST","model":"demo-model","receipt_id":"rcpt-0001","served_at":1750000000,"signature":"d5b005e093bde3b577faf270b7184b09e169cacb0ecb206b103bd2581f997db03da616175454b063323a23ac1dc68f1ce506c2a6eba8aa0561d5e724f0b80c03","workload_keyset_digest":"sha256:53a5cd44b30dcc51999754c719f2628a041f174ecbf9662a6f8e898a10cd9371"}';

const doc = JSON.parse(vecReceipt);
const flipLast = (hex) => hex.slice(0, -1) + (hex.endsWith("0") ? "1" : "0");
const pretty = JSON.stringify(Object.fromEntries(Object.entries(doc).reverse()), null, 2);

const cases = [
  { name: "valid", receipt: vecReceipt },
  { name: "valid, different encoding", receipt: pretty },
  { name: "served_at changed", receipt: JSON.stringify({ ...doc, served_at: 1750000001 }) },
  { name: "signature flipped", receipt: JSON.stringify({ ...doc, signature: flipLast(doc.signature) }) },
  { name: "response bytes changed", receipt: vecReceipt, response: '{"choices":[],"id":"chatcmpl-124"}' },
  { name: "request bytes changed", receipt: vecReceipt, request: '{"messages":[{"content":"hi!","role":"user"}],"model":"demo-model"}' },
  { name: "other established keyset", receipt: vecReceipt, established: "sha256:" + "00".repeat(32) },
];

// A real production receipt, saved by the Go live test
// (PHALA_API_KEY=... PRIVATEAI_CROSSCHECK_DIR=<workdir> go test ./provider/phala -run LiveInference).
try {
  const live = JSON.parse(await readFile(join(workdir, "live-receipt.json"), "utf8"));
  cases.push({ name: "live production receipt", ...live });
  cases.push({ name: "live receipt, response changed", ...live, response: live.response.replace(/.$/, " ") });
} catch {
  console.log("no live-receipt.json: checking the test vectors only");
}

const receipts = [];
for (const c of cases) {
  const request = c.request ?? vecRequest;
  const response = c.response ?? vecResponse;
  const established = c.established ?? vecDigest;
  const keyset = c.keyset ?? vecKeyset;
  const v = await aci.verifyReceipt(JSON.parse(c.receipt), keyset, established);
  let ok = v.ok;
  if (ok) {
    ok = (await aci.checkRequestBodyHash(v.payload, request)) && (await aci.checkResponseBodyHash(v.payload, response));
  }
  receipts.push({ name: c.name, receipt: c.receipt, request, response, established, keyset, ok });
}

const result = {
  verifier: "@phala/aci-verifier",
  report: {
    nonce,
    keysetDigest,
    reportData,
    bindingOk: binding.ok,
    composeOk: compose.ok,
    composeHash: compose.composeHash,
    quoteOk: quote.ok,
    quoteStatus: quote.status,
  },
  receiptKeyset: vecKeyset,
  receipts,
};
await writeFile(join(workdir, "ts-result.json"), JSON.stringify(result, null, 2));
console.log(JSON.stringify(result.report, null, 2));
console.log(receipts.map((r) => `${r.ok ? "ok  " : "FAIL"} ${r.name}`).join("\n"));
