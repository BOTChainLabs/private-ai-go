# Private AI SDK for Go（中文说明）

调用 TEE 机密推理的轻量 Go SDK，目前支持 Phala、NEAR AI，以及自行部署的 Private AI Gateway。[English](README.md)

```bash
go get github.com/BOTChainLabs/private-ai-go
```

每次调用都会强制完成证明校验：发送前确认对方运行在真实的 TEE 里，返回后确认结果没有被篡改。只有校验通过的结果才会返回，校验失败直接报错，不会降级到普通模型。

- 需要 Go 1.26 及以上，建议用最新的补丁版本编译
- API Key 由使用方提供（BYOK），费用由厂商直接收取
- SDK 不保存、不打印 API Key，Prompt 不经过 BotChain 的服务器

## 快速开始

```go
client, err := privateai.New(privateai.Config{
    Providers: map[privateai.ProviderID]privateai.ProviderConfig{
        privateai.Phala: {APIKey: os.Getenv("PHALA_API_KEY")},
        privateai.NEAR:  {APIKey: os.Getenv("NEARAI_API_KEY")},
    },
    // 只有清单里的模型可以调用
    Models: []privateai.ModelEntry{
        {Provider: privateai.Phala, Model: "z-ai/glm-5.3"},
        {Provider: privateai.NEAR, Model: "z-ai/glm-5.3-flash"},
    },
})
if err != nil {
    return err
}
defer client.Close()

res, err := client.Infer(ctx, privateai.InferRequest{
    Provider: privateai.Phala,
    Model:    "z-ai/glm-5.3",
    Messages: []privateai.Message{{Role: "user", Content: "hello"}},
})
if err != nil {
    return err // 校验没通过也会走到这里
}
fmt.Println(res.Content) // 走到这里，结果一定已经校验通过
```

`InferRequest.Params` 里的参数（temperature、max_tokens、tools 等）会原样透传给厂商。

## 流式调用

内容会边读边返回，但**在 Verify 成功之前，读到的内容都视为未验证**。需要可信结果的场景，请在 Verify 之后再使用内容。

NEAR 的流式响应只有网关签名，不能证明内容来自模型，所以 NEAR 的 Stream 会先完成一次已验证的调用，再作为一个完整的数据块返回。用法相同，只是不再逐字输出。

`Config.Timeout`（默认 2 分钟）限制每次 `Infer` 的总时长，包括远程证明和校验。流式调用只限制建立连接和 `Verify` 两步，不限制读取过程：回答生成得再久，也只受你自己的 context 控制。

```go
st, err := client.Stream(ctx, req)
if err != nil {
    return err
}
defer st.Close()

var sb strings.Builder
for {
    c, err := st.Recv()
    if errors.Is(err, io.EOF) {
        break
    }
    if err != nil {
        return err
    }
    sb.WriteString(c.Content)
}
if _, err := st.Verify(ctx); err != nil {
    return err // 流必须读到结尾才能校验
}
fmt.Println(sb.String(), st.Usage().TotalTokens)
```

## 校验内容

| 厂商 | 发送前 | 返回后 |
|---|---|---|
| Phala | 用新的 nonce 获取远程证明，校验 Intel TDX 报告和 TCB 状态、密钥集绑定、有效期；确认运行的是 Phala 生产环境的系统镜像、网关应用和 KMS；锁定 TLS 公钥 | 拉取 Receipt，校验 Ed25519 签名、请求和响应原始字节的哈希、上游 TEE 验证结果 |
| NEAR AI | 官方 SDK 校验网关和模型的远程证明（模型必须有 NVIDIA GPU 证明），锁定 TLS 公钥；确认网关和模型运行的是 NEAR 生产环境的系统镜像、应用和 KMS；请求加密到已验证的模型公钥（E2EE） | 必须是模型签名（provider_tee），且签名密钥属于已确认身份的模型 |
| Gateway | 同 Phala，按你配置的身份校验；消息内容始终端到端加密到网关 | 同 Phala |

Phala 的校验按 ACI 规范自行实现，已经用 ACI 官方测试向量和 Phala 官方验证库交叉验证。NEAR 的校验由 NEAR 官方 Go SDK 完成，本 SDK 在其上强制开启 E2EE、检查路由，并要求 NEAR SDK 建立的每个会话都落在已确认身份的机器上。

校验通过后，`res.Verification.Evidence` 里有应用、系统镜像、compose hash、TCB 状态及其对应的 Intel 安全公告编号，以及签名原文，可以按需存档。

## 策略

默认接受 TCB 状态为 `UpToDate` 和 `OutOfDate` 的机器。`OutOfDate` 表示平台缺少 `Evidence.AdvisoryIDs` 里列出的 Intel 安全公告的修复。默认接受它，是因为厂商的机器往往跟不上 Intel 的 TCB 更新（2026-11-11 时 NEAR AI 的网关就是 `OutOfDate`），拒绝它会让所有调用失败，直到厂商打完补丁。需要更严格时，可以按厂商单独配置：

```go
privateai.Phala: {
    APIKey: os.Getenv("PHALA_API_KEY"),
    Policy: privateai.Policy{
        AcceptedTCBStatuses: []string{"UpToDate"},
        ComposeHashes:       []string{"4dbdcd4f..."}, // 只接受指定的应用版本
    },
},
```

Phala 和 NEAR 生产环境的身份（系统镜像、应用、KMS）已内置在 SDK 中，Phala 的每套部署只接受它自己的应用、KMS 和系统镜像组合。厂商正常发布新版本不需要改动；如果厂商升级系统镜像，或者 NEAR 上线了新模型（新的应用 ID），校验会失败，错误信息里带有新值。跟厂商确认后，可以先自行加上，不用等 SDK 发版：

```go
privateai.NEAR: {
    APIKey:        os.Getenv("NEARAI_API_KEY"),
    ExtraOSBuilds: []privateai.OSMeasurement{{MRTD: "...", RTMR0: "...", RTMR1: "...", RTMR2: "..."}},
    ExtraAppIDs:   []string{"..."}, // NEAR 模型的应用 ID
},
```

NEAR 的 GPU 校验需要访问 NVIDIA 的证明服务（nras.attestation.nvidia.com），部署前请确认服务器能访问。

## 端到端加密（E2EE）

Phala 的网关支持 E2EE v2（[规范](https://github.com/Dstack-TEE/private-ai-gateway/blob/main/spec/e2ee-v2.md)）。设置 `E2EE: true` 后，消息内容加密到网关已验证的公钥，回答用每次请求新生成的密钥加密返回：

```go
privateai.Phala: {APIKey: os.Getenv("PHALA_API_KEY"), E2EE: true},
```

Receipt 校验照常进行：网关解密后会重新序列化请求再计算哈希，SDK 能准确算出这份字节。加密的只是内容：消息内容，以及回答的内容和推理过程。其他部分只走已锁定的 TLS，包括 API Key、tools 和 response_format 等参数，以及回答里的工具调用、拒答说明和 logprobs。`Evidence.E2EE` 记录使用的加密套件。NEAR 始终使用它自己的 E2EE。

## 自行部署的网关

`privateai.Gateway` 用来校验别人部署的 Private AI Gateway（比如 BotChain AI Gateway），按运营方公布的身份校验：

```go
privateai.Gateway: {
    APIKey:  os.Getenv("GATEWAY_API_KEY"),
    BaseURL: "https://gateway.example.com",
    Identity: &privateai.GatewayIdentity{
        AppIDs:        []string{"..."}, // 部署的 dstack 应用 ID
        OS:            []privateai.OSMeasurement{{MRTD: "...", RTMR0: "...", RTMR1: "...", RTMR2: "..."}},
        ComposeHashes: []string{"..."}, // 运营方公布的版本
        // KeyProviders 默认是 Phala Cloud 的 KMS
    },
},
```

Gateway 始终开启 E2EE，并且必须填写 `Identity.ComposeHashes`：运营方随时可以给自己的应用授权新的 compose，只看应用 ID、系统镜像和 KMS 会照单全收，只有锁定版本才能保证跑的是你审核过的版本。版本要写在 `Identity.ComposeHashes` 里，Gateway 不接受 `Policy.ComposeHashes`。

网关的 TLS 必须在 TEE 内终止，TLS 公钥要列在已验证的密钥集里，Phala 自己的网关就是这样。如果 TLS 在 TEE 外终止（比如 Phala Cloud 的入口），密钥集里没有 TLS 公钥，SDK 默认拒绝，除非设置 `AllowTLSOutsideTEE`。设置之后，E2EE 能防住网关运营方看到消息内容，但防不住终止 TLS 的那一方：E2EE v2 不绑定客户端公钥，对方可以在重放窗口内换上自己的公钥重发请求，读到回答。对方还能改写证明报告里 TEE 没有签名的部分，所以这种模式下不管网关报告自己是哪种服务方式，每张 Receipt 都必须带有已验证的上游 TEE 会话。`Evidence.TLSPinned` 会标明属于哪种情况。

## 错误处理

所有错误都可以用 `errors.As` 取出 `*privateai.Error`，按 `Code` 区分（常量如 `privateai.CodeAttestationFailed`）：

| 错误码 | 含义 |
|---|---|
| INVALID_REQUEST | 请求参数不合法，请求不会发出 |
| MODEL_NOT_ALLOWED | 模型不在清单内，请求不会发出 |
| ATTESTATION_FAILED | 远程证明校验失败 |
| TLS_PIN_MISMATCH | TLS 公钥与证明不一致，请求不会发出 |
| RECEIPT_INVALID | Receipt 或签名校验失败 |
| ROUTE_NOT_TEE | 实际路由不是 TEE |
| EVIDENCE_UNAVAILABLE | 证明或签名暂时取不到 |
| VERIFIER_UNAVAILABLE | Intel、NVIDIA 等外部证明服务不可用 |
| PROVIDER_ERROR | 厂商返回错误，如鉴权失败、余额不足、限流 |

请求发出后才失败的错误，会附带 `Verification`，里面有状态（Failed 或 Unverified）和原因。调用方自己取消 context 时，返回的就是 context 本身的错误。

## Demo

```sh
PHALA_API_KEY=... go run ./examples/demo "Say hi"
NEARAI_API_KEY=... go run ./examples/demo -provider near -stream "Say hi"
PHALA_API_KEY=... NEARAI_API_KEY=... go run ./examples/web   # 网页聊天，打开 http://127.0.0.1:8080
```

网页版每条回答旁边都有证明面板：通过了哪些校验、对应的证据，以及可下载的证明文件。Phala 流式回答在 Receipt 验签通过前标为“未验证”；NEAR 校验通过后一次性返回。默认只监听本机，只响应发往 localhost 的请求，接口拒绝跨站请求，其他网页无法借用它。每条消息都消耗 Key 的余额，所以要对外提供服务，必须同时设置 `DEMO_PASSWORD`（HTTP 基本认证）和 TLS（`-addr :8443 -tls-cert cert.pem -tls-key key.pem`）。

## 测试

```sh
make check                                                       # gofmt、go vet、go test -race（与 CI 相同）
PRIVATEAI_LIVE=1 go test ./provider/phala -run Live -v           # Phala 线上预检，无需 Key
PHALA_API_KEY=... go test ./provider/phala -run LiveInference -v  # Phala 线上调用（非流式、流式、拒绝非 TEE 模型）
NEARAI_API_KEY=... go test ./provider/near -run Live -v          # NEAR 线上调用
```

与 Phala 官方验证库的交叉验证见 [tools/crosscheck](tools/crosscheck/README.md)。E2EE 与真实网关的联调见 [tools/gatewaycheck](tools/gatewaycheck/README.md)（`make interop`，需要 Docker），JSON 序列化与 Rust serde_json 的对比见 [tools/serdecheck](tools/serdecheck/README.md)（`make serdecheck`）。

## 目录结构

```
privateai.go      对外入口：New、Infer、Stream、ListModels、Close
core/             公共类型、错误码、Provider 接口
provider/phala/   Phala 和自建网关：ACI 预检、TLS 绑定、Receipt 验签、E2EE
provider/near/    NEAR AI：封装官方 Go SDK
internal/oai/     OpenAI 兼容的请求、响应和 SSE 解析
internal/canon/   ACI 文档的规范化（JCS）
internal/e2ee/    E2EE v2 客户端（X25519 + HKDF-SHA256 + AES-256-GCM）
internal/serdejson/ 与网关（Rust serde_json）一致的 JSON 读写
internal/tdx/     TDX Quote 解析、系统镜像和应用身份校验（两家共用）
examples/demo/    命令行 Demo
examples/web/     网页聊天 Demo
tools/crosscheck/ 与 Phala 官方验证库的交叉验证
tools/gatewaycheck/ 与真实网关的 E2EE 联调
tools/serdecheck/ 与 Rust serde_json 的序列化对比
```
