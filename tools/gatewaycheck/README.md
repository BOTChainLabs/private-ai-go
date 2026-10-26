# E2EE interop with the real gateway

An end-to-end test of E2EE v2 against the Private AI Gateway itself, the
Rust code Phala runs at inference.phala.com: the SDK encrypts a chat request,
the gateway decrypts it and forwards it to a mock upstream served by the Go
test, then encrypts the answer and signs a receipt. The test checks that:

- the gateway forwarded exactly the messages that were encrypted;
- the receipt verifies, and its request hash is the one the SDK predicted
  for the request the gateway decrypted (E2EE v2 §8);
- buffered and streamed answers, and reasoning, decrypt;
- a replayed request is refused.

The gateway runs on dstack's TEE simulator, so its attestation is not
genuine and is not checked here; the unit tests and the live tests cover
attestation.

```sh
docker compose -f tools/gatewaycheck/compose.yaml up -d --build   # first build ~15 min
PRIVATEAI_GATEWAY_INTEROP=http://127.0.0.1:18086 go test ./provider/phala -run GatewayInterop -v
docker compose -f tools/gatewaycheck/compose.yaml down
```

The gateway reaches the mock at `host.docker.internal:18087`; set
`PRIVATEAI_GATEWAY_MOCK_ADDR` to listen elsewhere.

Last run 2026-10-26, gateway commit 22d08e24: buffered and streaming both
pass, with messages that include HTML, U+2028, control characters, emoji,
array-like text, empty content and 10 KB of text, and float, large integer
and nested parameters.
