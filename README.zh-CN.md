# Private AI SDK for Go（中文说明）

调用 TEE 机密推理的轻量 Go SDK，目前支持 Phala 和 NEAR AI。[English](README.md)

```bash
go get github.com/BOTChainLabs/private-ai-go
```

每次调用都会强制完成证明校验：发送前确认对方运行在真实的 TEE 里，返回后确认结果没有被篡改。只有校验通过的结果才会返回，校验失败直接报错，不会降级到普通模型。

- 需要 Go 1.25.8 及以上（依赖 NEAR 官方 Go SDK）
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

Phala 的校验按 ACI 规范自行实现，已经用 ACI 官方测试向量和 Phala 官方验证库交叉验证。NEAR 的校验由 NEAR 官方 Go SDK 完成，本 SDK 在其上强制开启 E2EE 并检查路由。

校验通过后，`res.Verification.Evidence` 里有应用、系统镜像、compose hash、TCB 状态和签名原文，可以按需存档。

## 策略

默认只接受 TCB 状态为 UpToDate 和 OutOfDate 的机器。需要更严格时，可以按厂商单独配置：

```go
privateai.Phala: {
    APIKey: os.Getenv("PHALA_API_KEY"),
    Policy: privateai.Policy{
        AcceptedTCBStatuses: []string{"UpToDate"},
        ComposeHashes:       []string{"4dbdcd4f..."}, // 只接受指定的应用版本
    },
},
```

Phala 和 NEAR 生产环境的身份（系统镜像、应用、KMS）已内置在 SDK 中。厂商正常发布新版本不需要改动；如果厂商升级系统镜像，或者 NEAR 上线了新模型（新的应用 ID），校验会失败，错误信息里带有新值。跟厂商确认后，可以先自行加上，不用等 SDK 发版：

```go
privateai.NEAR: {
    APIKey:        os.Getenv("NEARAI_API_KEY"),
    ExtraOSBuilds: []privateai.OSMeasurement{{MRTD: "...", RTMR0: "...", RTMR1: "...", RTMR2: "..."}},
    ExtraAppIDs:   []string{"..."}, // NEAR 模型的应用 ID
},
```

NEAR 的 GPU 校验需要访问 NVIDIA 的证明服务（nras.attestation.nvidia.com），部署前请确认服务器能访问。

## 错误处理

所有错误都可以用 `errors.As` 取出 `*privateai.Error`，按 `Code` 区分：

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

请求发出后才失败的错误，会附带 `Verification`，里面有状态（Failed 或 Unverified）和原因。

## Demo

```sh
PHALA_API_KEY=... go run ./examples/demo "Say hi"
NEARAI_API_KEY=... go run ./examples/demo -provider near -stream "Say hi"
PHALA_API_KEY=... NEARAI_API_KEY=... go run ./examples/web   # 网页聊天，打开 http://127.0.0.1:8080
```

网页版每条回答都显示校验结果。Phala 流式回答在 Receipt 验签通过前标为“未验证”；NEAR 校验通过后一次性返回。默认只监听本机；要对外开放，用 `-addr` 并设置 `DEMO_PASSWORD`，因为每条消息都消耗 Key 的余额。

## 测试

```sh
go test -race ./...                                              # 全部单元测试
PRIVATEAI_LIVE=1 go test ./provider/phala -run Live -v           # Phala 线上预检，无需 Key
PHALA_API_KEY=... go test ./provider/phala -run LiveInference -v  # Phala 线上调用（非流式、流式、拒绝非 TEE 模型）
NEARAI_API_KEY=... go test ./provider/near -run Live -v          # NEAR 线上调用
```

与 Phala 官方验证库的交叉验证见 [tools/crosscheck](tools/crosscheck/README.md)。

## 目录结构

```
privateai.go      对外入口：New、Infer、Stream、ListModels、Close
core/             公共类型、错误码、Provider 接口
provider/phala/   Phala：ACI 预检、TLS 绑定、Receipt 验签
provider/near/    NEAR AI：封装官方 Go SDK
internal/oai/     OpenAI 兼容的请求、响应和 SSE 解析
internal/canon/   ACI 文档的规范化（JCS）
examples/demo/    命令行 Demo
examples/web/     网页聊天 Demo
tools/crosscheck/ 与 Phala 官方验证库的交叉验证
```
