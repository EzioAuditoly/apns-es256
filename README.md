# apns-es256

> 独立实现的 Apple Push Notification service (APNs) 客户端：自己组装 ES256 provider token，HTTP/2 直连 `api.push.apple.com`，并在生产端点遇到 `BadDeviceToken` 时自动回落到沙箱端点。

---

## 一句话定位

一个**不依赖 PyJWT** 的极简 APNs 推送库：只做三件事——把 ECDSA 的 DER 签名转成 JOSE 要求的原始 `R‖S` 格式、签出 provider token、通过 HTTP/2 把通知投出去，并把 Apple 的错误码收敛成可判断"该重试还是该删令牌"的分类。

---

## 为什么要手写 ES256，而不是用 PyJWT

`PyJWT` 的 `crypto` extra 对 `cryptography` 的版本有较紧的约束。在下面这些真实场景里，它带来的麻烦往往大于它省下的代码：

- 运行环境里的 `cryptography` 来自**系统包管理器**（`apt`/`apk`/`brew`），版本由发行版钉死；
- 同环境里有别的依赖（如某些 SSL、gRPC、云 SDK）已经把 `cryptography` 锁在某个区间；
- 容器基础镜像只允许离线安装，`pip` 无法重新求解整个依赖图。

此时 `pip install "pyjwt[crypto]"` 常见两种结果：**要么把 `cryptography` 升降级**，**要么直接报版本冲突**。而 `cryptography` 一旦被换版本，受影响的不只是 JWT——同环境下所有 TLS/证书/加密调用都会跟着变，属于典型的"为了发个推送动了地基"。

而 APNs 的 provider token 本身**极其简单**：

```
header  = {"alg": "ES256", "kid": "<KeyID>"}
claims  = {"iss": "<TeamID>", "iat": <当前时间戳>, "exp": <iat + ttl>}
token   = base64url(header) + "." + base64url(claims) + "." + base64url(签名)
```

固定头、固定载荷、一次 `ECDSA-P256-SHA256` 签名。（Apple 实际只校验 `iss` 与 `iat`；
`exp` 是 JWT 常规字段，带上它可让下游解析器自行判断过期，不写也无妨。）
为这点功能引入一个会参与版本求解的第三方 JWT 库，风险收益不成比例。所以本库只依赖
`cryptography` 的 `ec` / `hashes` / `serialization` 三个子模块，**且是延迟导入**——
不调用签名时才不会去碰它。

---

## 安装

```bash
# 完整功能：能签名 + 能发 HTTP/2 请求
pip install ".[all]"

# 也可以按需拆开
pip install ".[crypto]"      # 只要 ES256 签名能力
pip install ".[http2]"       # 只要 HTTP/2 传输能力
```

> ⚠️ **本库核心不依赖任何第三方包。** `DER ↔ 原始 R‖S` 的转换、错误码分类、回落与重试逻辑全部是纯标准库实现，只有"真正签名"和"真正发 HTTP/2 请求"这两步需要 `cryptography` 与 `httpx`。因此你完全可以用 `signer=` 注入自己的签名实现，从而彻底不引入 `cryptography`。

**要求**：Python ≥ 3.9，且必须能装 `h2`（APNs 只接受 HTTP/2；缺 `h2` 时本库会直接报错而不是让请求以 HTTP/1.1 失败）。

---

## 最小用法示例

### 1. 从环境变量读取凭据（推荐）

```bash
export APNS_KEY_ID=ABCDE12345            # .p8 密钥的 Key ID
export APNS_TEAM_ID=ABCDE12345           # Apple Developer Team ID
export APNS_BUNDLE_ID=com.example.app    # 作为 apns-topic
export APNS_KEY_PATH=/etc/apns/AuthKey_XXXXXXXXXX.p8
```

```python
from apns_es256 import ApnsClient, ApnsConfig

config = ApnsConfig.from_env()

with ApnsClient(config) as client:
    result = client.send(
        device_token="0f1e2d3c4b5a69788796a5b4c3d2e1f0" * 2,   # 64 位十六进制
        payload={"aps": {"alert": "你好", "sound": "default", "badge": 1}},
    )

    if result.ok:
        print("投递成功", result.apns_id)
    else:
        print("失败", result.response.status, result.response.reason,
              "分类:", result.error_class, "可重试:", result.retryable)
```

### 2. 私钥内容直接传入（适合从密管系统读出的场景）

```python
from apns_es256 import ApnsClient, ApnsConfig

config = ApnsConfig(
    key_id="ABCDE12345",
    team_id="ABCDE12345",
    bundle_id="com.example.app",
    key_pem=read_secret_from_vault(),   # PKCS#8 PEM 文本
)
client = ApnsClient(config)
```

### 3. 后台/静默推送与合并通知

```python
result = client.send(
    device_token=token,
    payload={"aps": {"content-available": 1}},
    push_type="background",   # apns-push-type
    priority=5,               # 省电模式
    collapse_id="chat-42",    # 同类通知合并
    expiration=0,             # 不存储，只投一次
)
```

### 4. 注册错误回调，自动清理失效令牌

```python
from apns_es256 import ApnsReason, ErrorClass

def drop_token(response):
    # 令牌已失效，应从数据库删除，**不要**重试
    db.delete_device_token(token)

client = ApnsClient(
    config,
    on_reason={
        ApnsReason.UNREGISTERED: drop_token,
        ApnsReason.BAD_DEVICE_TOKEN: lambda r: log.warning("令牌无效"),
    },
)
```

### 5. 完全不用 cryptography（注入自定义签名器）

```python
from apns_es256 import ApnsClient, ApnsConfig, TokenProvider

def my_signer(signing_input: bytes, _key) -> bytes:
    """必须返回 64 字节原始 R‖S 签名。"""
    return hsm_sign_p256_sha256(signing_input)

config = ApnsConfig(key_id="...", team_id="...", bundle_id="com.example.app",
                    key_pem="placeholder")   # key_pem 仅用于通过配置校验
client = ApnsClient(
    config,
    token_provider=TokenProvider(
        key_id=config.key_id, team_id=config.team_id, signer=my_signer
    ),
)
```

---

## DER → `R‖S` 的说明

这是本库存在的最核心理由，也是最容易踩的坑。

**ECDSA 签名有两种互不兼容的编码：**

| 编码 | 结构 | 长度 | 谁在用 |
|---|---|---|---|
| **DER** | `SEQUENCE { INTEGER r, INTEGER s }` | **可变**（P-256 下 70–72 字节） | OpenSSL、`cryptography`、Java、Go 等原生 API |
| **原始 `R‖S`**（JOSE / RFC 7518 §3.4） | `r` 的定长大端字节串 ‖ `s` 的定长大端字节串 | **固定**（P-256 → 32 + 32 = **64** 字节） | JWT / APNs provider token |

DER 里每个 `INTEGER` 用**最短**形式编码，所以：

- `r` 或 `s` 若高位为 0，会被压短 → 可能只有 **31** 字节；
- `r` 或 `s` 若最高位是 1，必须补一个 `0x00` 前缀避免被当成负数 → 可能变成 **33** 字节。

这就是 DER 签名长度在 70/71/72 之间浮动的原因。而 APNs 要的是**每个分量固定左补零到 32 字节**的定长拼接。**把 DER 原样填进 JWT 签名，Apple 会回 `403 InvalidProviderToken`**，而且报错信息完全不会提示是编码问题——这是最常见的排查黑洞。

本库的处理（`apns_es256.der`，**纯标准库**）：

```python
from apns_es256 import der_to_raw, raw_to_der, signature_size

signature_size("P-256")          # 64
raw = der_to_raw(der_signature)  # DER(70~72B) → 定长 64B
der = raw_to_der(raw)            # 逆向，用于往返验证
```

实现上严格校验：必须是 `SEQUENCE`、长度字段必须用最短形式、`INTEGER` 不得为负、`SEQUENCE` 声明长度必须与剩余字节精确吻合、分量不得超出曲线位宽。已经**是**原始格式的输入不会被静默接受——它会因为缺少 `SEQUENCE` 标签而抛 `DerError`，避免"没转换"被误当成"转换成功"。

---

## 生产 / 沙箱回落策略

APNs 有两个**完全隔离**的端点：

- 生产：`https://api.push.apple.com`
- 沙箱：`https://api.sandbox.push.apple.com`

关键事实：**设备令牌是分开的**。Xcode 从本机直接装的 dev build 拿到的是**沙箱令牌**，TestFlight / App Store 装的拿到的是**生产令牌**。把沙箱令牌发到生产端点，Apple 的回应是 `400 BadDeviceToken`——**这个报错并不代表令牌失效**。

这就是回落策略的动机。默认行为：

```
生产端点 → 收到 400 BadDeviceToken
         → 用同一令牌向沙箱端点重发一次
         → 结果里 fell_back=True 标识发生过回落
```

```python
result = client.send(device_token=token, payload=payload)
print(result.environment)   # 最终生效的环境
print(result.fell_back)     # 是否回落过
print(result.tried)         # ('production', 'sandbox')
print(result.attempts)      # 实际请求次数
```

**设计取舍（有意为之）：**

1. **只做生产 → 沙箱单向回落。** 沙箱端点对某些生产令牌是永久拒绝的，反向回落没有意义，还会掩盖"用了生产令牌测沙箱"这类配置错误。
2. **回落只在 `BadDeviceToken` 上触发**，不对 `Unregistered` 触发——后者是令牌真失效，该做的是从库里删掉。
3. **回落只做一次**，不来回横跳。
4. 可用 `sandbox_fallback=False` 关掉；也可用 `environment=ApnsEnvironment.SANDBOX` 直接指定起始环境（适合内测环境整体走沙箱）。

**重试语义**（与回落相互独立）：

| 错误分类 | 代表 reason | 是否重试 |
|---|---|---|
| `unregistered` | `Unregistered`, `410` | ❌ 应删除令牌 |
| `token_mismatch` | `BadDeviceToken`, `DeviceTokenNotForTopic` | ❌ 仅触发一次沙箱回落 |
| `auth` | `InvalidProviderToken`, `ExpiredProviderToken` | 自动重签 token 后重试一次 |
| `bad_request` | `PayloadTooLarge`, `BadTopic`, `MissingTopic` | ❌ 改代码 |
| `retryable` | `InternalServerError`, `ServiceUnavailable`, `Shutdown`, 超时 | ✅ 指数退避 |
| `throttled` | `TooManyRequests`, `TooManyProviderTokenUpdates` | ✅ 指数退避（需放慢） |

退避为 `retry_backoff * 2**(n-1)`，可用 `retry_backoff` / `max_retries` / `jitter` 调节。

**provider token 缓存**：Apple 允许同一个 token 复用最多 1 小时，并且对重签频率有限制（`TooManyProviderTokenUpdates`）。本库默认缓存 **50 分钟**，收到 `ExpiredProviderToken` / `InvalidProviderToken` 时自动作废重签。

---

## 已知限制

1. **不支持 certificate-based（.p12 + TLS 客户端证书）推送。** 本库只实现 token-based（.p8 + JWT）认证。前者是 Apple 的旧方案，但仍在部分老项目里使用。
2. **不做连接池调优与并发编排。** 底层用 `httpx.Client` 的默认连接管理；`send_many` 是**顺序**发送，刻意不内置并发。大规模推送建议调用方自建并发层（并注意 APNs 对单连接并发流数量的限制）。
3. **不内置日志。** 库不做任何 `logging` 调用，以免污染使用方的日志树；需要观测就挂 `on_reason` 回调。
4. **只支持单主题（`apns-topic`）。** 不支持 VoIP / `com.apple.developer.usernotifications.communication` 等特殊主题的多 topic 路由——可通过 `topic=` 参数逐条覆盖。
5. **不校验 payload 的语义。** 只校验 JSON 可序列化 + 不超过 4KB；`aps` 结构是否合法由 Apple 判定（它会回 `BadMessage`），本库把该 reason 归类为 `bad_request`。
6. **不自动刷新 JWT 的时钟偏移。** 若运行机器时钟比 Apple 慢/快较多，可能出现 `ExpiredProviderToken`；本库在收到该错误时会重签一次以自愈，但不做 NTP 校正。
7. **`send_many` 不保证原子性**，也不聚合结果——单个失败不影响后续，结果逐个返回。
8. **未在真实 Apple 生产环境端到端验证过。** 本仓库的测试全部是离线 stub/monkeypatch（见 `tests/`），**从未真正联网调用 Apple 端点**。因此端到端的真实投递行为需要使用者自行在真机上验证。

---

## 仍需使用者自行确认的空白

以下内容需由发布者自行确认后再对外开源：

1. **版权归属（仍未确认）**：作者署名与仓库地址**已填写**（见 `LICENSE` 与
   `pyproject.toml`）。但**署名 ≠ 版权归属已澄清**：若代码编写于在职期间且与本职工作
   相关，版权可能归属雇主。**在公开发布前请先确认你确实有权以 MIT 许可开源这份代码。**
2. **是否在 README / 包元数据中提及公司或产品名**：当前 README 与元数据**完全没有**出现任何公司名、产品名、内部系统名或组织标识，全部用 `com.example.app`、`ABCDE12345`、`AuthKey_XXXXXXXXXX.p8` 这类占位符。是否要在"致谢"或"来源"中提及公司，需由你决定——**在未获得公司明确许可前，建议保持不提。**
3. **开源许可审批**：以 MIT 开源是否需要走公司内部的开源审批（Open Source Review）流程。
4. **包名可用性**：`apns-es256` 是否与 PyPI 上已有项目冲突，发布前需查重。
5. **真实端点验证**：请用你自己的 Apple Developer 账号 + 真机 dev build，分别验证生产与沙箱两条路径，确认回落行为符合预期。
6. **是否公开仓库**：本仓库已初始化 git 且**刻意未配置任何 remote**。若你的推送服务曾把
   `.p8` 私钥提交进业务仓库，请先处理该凭据泄漏问题（吊销并重建 Key）再公开本库。

---

## 许可

[MIT](LICENSE)
