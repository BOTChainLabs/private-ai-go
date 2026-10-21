# Cross-check with Phala's official verifier

A differential test: Phala's TypeScript verifier and this SDK verify the same
live attestation report and the same receipt cases, and must reach identical
verdicts. Run it after changing anything in `provider/phala`.

```sh
# 1. Install the official verifier in its own directory (install scripts off).
mkdir -p /tmp/aci-ts && cd /tmp/aci-ts
npm init -y >/dev/null && npm install --ignore-scripts @phala/aci-verifier@0.8.0

# 2. Capture a live report with a known nonce.
W=/tmp/aci-crosscheck && mkdir -p $W
N=$(openssl rand -hex 32) && echo -n $N > $W/nonce.txt
curl -sSf "https://inference.phala.com/v1/aci/attestation?nonce=$N" -o $W/report.json

# 3. Optional: save a real production receipt with its exact bytes.
PHALA_API_KEY=... PRIVATEAI_CROSSCHECK_DIR=$W go test ./provider/phala -run LiveInference/infer

# 4. Official verdicts, then ours on the same bytes.
node tools/crosscheck/crosscheck.mjs /tmp/aci-ts/node_modules/@phala/aci-verifier/dist/index.js $W
PRIVATEAI_CROSSCHECK_DIR=$W go test ./provider/phala -run CrossCheck -v
```

Last run 2026-10-20 against @phala/aci-verifier 0.8.0: all 10 comparisons
agree (report binding, compose hash, TCB status; 7 receipt vectors including
tampering and re-encoding; a real production receipt, accepted, and the same
receipt with one response byte changed, rejected).
