"""APNs 客户端（抽取自源实现的 ``APNsService``）。

抽取与改写说明
--------------
原样保留的行为：

* ``send()`` 的 URL 形状 ``{base}/3/device/{device_token}``；
* 请求头集合：``authorization`` / ``apns-topic`` / ``apns-push-type`` /
  ``apns-priority`` / ``content-type``；
* ``topic=None`` 时回落到 ``bundle_id``；
* **生产端点 ``400 BadDeviceToken`` 自动回落沙箱并重发一次**，含源实现里
  ``'sandbox' not in url`` 这个巧妙的反向回落守卫；
* ``send_alert()`` 构造 ``aps.alert.title/body + badge + sound`` 的形状，
  以及 ``custom_data`` 顶层合并（不是塞进 ``aps``）；
* 拿不到 token 时即失败（源实现返回 ``{'success': False, 'error': ...}``）。

有意改写的行为（详见 EXTRACT-PLAN.md）：

1. 去掉与公司业务的耦合：源文件的 ``JPushService``、全局单例
   ``apns_service``/``jpush_service``、``init_push_services``、
   ``send_push_notification``（DAO 查库 + iOS/Android 分流）**均未抽取**。
2. ``except Exception`` 一把抓 → 结构化错误分类（:mod:`.errors`），
   区分「该重试」「该删令牌」「该改代码」。
3. 新增**退避重试**（源实现无重试，``max_retries`` 默认 0 以保持原行为）。
4. 新增**设备令牌格式校验**：源实现把令牌直接拼进 URL path，缺校验；
   本库强制 64 位十六进制，防路径注入。
5. 新增 payload 4KB 上限校验（Apple 限制；源实现无校验）。
6. 返回结构 :class:`DeliveryResult` 保留 ``success``/``status_code``/``error``
   语义，但把 Apple 的 ``reason`` 解析成枚举。
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Sequence

from .config import ApnsConfig, ApnsEnvironment
from .errors import (
    ApnsConfigError,
    ApnsDeliveryError,
    ApnsReason,
    ApnsResponse,
    ApnsTransportError,
    ErrorClass,
    parse_reason,
)
from .jwt import TokenProvider
from .transport import (
    HttpxTransport,
    Transport,
    TransportRequest,
    TransportResponse,
)

#: 设备令牌必须是 64 位十六进制（32 字节）。同时用于防止路径注入。
_DEVICE_TOKEN_RE = re.compile(r"^[0-9a-fA-F]{64}$")

#: Apple 对单条通知载荷的大小限制（4KB）。
MAX_PAYLOAD_BYTES = 4096

Payload = Mapping[str, Any]


@dataclass(frozen=True)
class DeliveryResult:
    """一次 ``send`` 的结果。

    兼容源实现的字典语义：``result["success"]`` / ``result["status_code"]`` /
    ``result["error"]`` 均可用（见 :meth:`as_dict`）。
    """

    response: ApnsResponse
    environment: ApnsEnvironment
    fell_back: bool = False
    attempts: int = 1
    tried: tuple[ApnsEnvironment, ...] = ()

    @property
    def ok(self) -> bool:
        """是否投递成功（对应源实现的 ``success``）。"""
        return self.response.ok

    @property
    def success(self) -> bool:
        """源实现字典键 ``success`` 的别名。"""
        return self.ok

    @property
    def status_code(self) -> int:
        """源实现字典键 ``status_code`` 的别名。"""
        return self.response.status

    @property
    def apns_id(self) -> str | None:
        """Apple 侧请求 ID，排障时上报给 Apple 用。"""
        return self.response.apns_id

    @property
    def error_class(self) -> ErrorClass:
        """失败分类。"""
        return self.response.error_class

    @property
    def retryable(self) -> bool:
        """是否值得重试。"""
        return self.response.retryable

    def as_dict(self) -> dict[str, Any]:
        """转成源实现风格的字典，便于调用方平滑迁移。

        成功 → ``{'success': True}``（与源实现完全一致）。
        失败 → ``{'success': False, 'status_code': int, 'error': <reason 文本>}``。
        """
        if self.ok:
            return {"success": True}
        reason = self.response.reason.value if self.response.reason else None
        return {
            "success": False,
            "status_code": self.response.status,
            "error": reason or "",
        }

    def __getitem__(self, key: str) -> Any:
        """支持 ``result['success']`` 这类旧式取值。"""
        return self.as_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        """支持 ``result.get('success')`` 这类旧式取值。"""
        return self.as_dict().get(key, default)


def validate_device_token(device_token: str) -> str:
    """校验设备令牌格式并归一化为小写。

    校验存在的理由：令牌会被直接拼进 URL path（源实现如此），
    ``../`` 之类字符可能把请求引到意外路径。
    """
    if not isinstance(device_token, str):
        raise ApnsConfigError(f"device_token 必须是字符串，收到 {type(device_token).__name__}")
    cleaned = device_token.strip()
    if not cleaned:
        raise ApnsConfigError("device_token 不能为空")
    if not _DEVICE_TOKEN_RE.match(cleaned):
        raise ApnsConfigError("device_token 必须是 64 位十六进制字符（APNs 设备令牌格式）")
    return cleaned.lower()


def build_alert_payload(
    *,
    title: str,
    body: str,
    badge: int = 0,
    sound: str = "default",
    custom_data: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    """构造 ``send_alert`` 的载荷（忠实复刻源实现的结构）。

    注意 ``custom_data`` 是**顶层合并**进 payload，而不是放进 ``aps``——
    这与源实现一致。
    """
    aps_payload: dict[str, Any] = {
        "aps": {
            "alert": {"title": title, "body": body},
            "badge": badge,
            "sound": sound,
        }
    }
    if custom_data:
        aps_payload.update(custom_data)
    return aps_payload


class ApnsClient:
    """直连 APNs 的客户端。

    典型用法::

        from apns_es256 import ApnsClient, ApnsConfig

        config = ApnsConfig.from_env()     # 读 APNS_KEY_ID / APNS_TEAM_ID / ...
        with ApnsClient(config) as client:
            result = client.send(
                device_token="0" * 64,
                payload={"aps": {"alert": "hi", "sound": "default"}},
            )
            if not result.ok:
                print(result.status_code, result.response.reason)

    回落策略
    --------
    生产端点对**沙箱令牌**会回 ``400 BadDeviceToken``（dev build 装真机拿到的就是
    沙箱令牌），因此该报错并不代表令牌失效。默认行为与源实现一致：生产端点收到
    ``BadDeviceToken`` 时用同一令牌向沙箱端点重发一次，``fell_back`` 标为 True。

    只在**生产→沙箱**单向回落（源实现用 ``'sandbox' not in url`` 保证这一点）。
    """

    def __init__(
        self,
        config: ApnsConfig,
        *,
        transport: Transport | None = None,
        token_provider: TokenProvider | None = None,
        sleep: Callable[[float], None] = time.sleep,
        jitter: Callable[[float], float] | None = None,
    ) -> None:
        self.config = config
        self._transport = transport if transport is not None else HttpxTransport()
        self._owns_transport = transport is None
        self._sleep = sleep
        self._jitter = jitter or (lambda base: 0.0)

        if token_provider is not None:
            self._tokens = token_provider
        else:
            self._tokens = TokenProvider(
                key_id=config.key_id,
                team_id=config.team_id,
                key_path=config.key_path,
            )

    # ------------------------------------------------------------------ 公开 API

    def send(
        self,
        device_token: str,
        payload: Payload,
        *,
        topic: str | None = None,
        push_type: str = "alert",
        priority: int = 10,
        expiration: int | None = None,
        collapse_id: str | None = None,
        environment: ApnsEnvironment | None = None,
        extra_headers: Mapping[str, str] | None = None,
        raise_on_error: bool = False,
    ) -> DeliveryResult:
        """向单个设备发送一条通知。

        :param device_token: 64 位十六进制设备令牌。
        :param payload: 通知载荷，通常形如 ``{"aps": {...}}``。
        :param topic: 覆盖 ``apns-topic``；默认用 ``config.bundle_id``。
        :param push_type: ``apns-push-type``，如 ``alert``/``background``。
        :param priority: ``apns-priority``（10 立即，5 省电）。
        :param expiration: ``apns-expiration`` UNIX 时间戳；``0`` 表示只投一次。
        :param collapse_id: ``apns-collapse-id``，用于合并同类通知。
        :param environment: 覆盖起始环境。
        :param extra_headers: 额外请求头。
        :param raise_on_error: 失败时抛 :class:`ApnsDeliveryError`。
        """
        token_value = validate_device_token(device_token)
        body = self._encode_payload(payload)
        active_topic = self.config.topic if topic is None else topic

        start_env = environment or self.config.environment
        tried: list[ApnsEnvironment] = []
        attempts = 0

        # —— 阶段一：起始环境 + 可重试错误的退避重试 ——
        response, used = self._attempt(
            environment=start_env,
            device_token=token_value,
            body=body,
            topic=active_topic,
            push_type=push_type,
            priority=priority,
            expiration=expiration,
            collapse_id=collapse_id,
            extra_headers=extra_headers,
        )
        attempts += used
        tried.append(start_env)

        # —— 阶段二：生产 BadDeviceToken → 沙箱回落（只做一次，单向）——
        fell_back = False
        final_env = start_env
        if (
            response.reason is ApnsReason.BAD_DEVICE_TOKEN
            and start_env is ApnsEnvironment.PRODUCTION
            and self.config.sandbox_fallback
        ):
            fell_back = True
            final_env = ApnsEnvironment.SANDBOX
            response, used = self._attempt(
                environment=final_env,
                device_token=token_value,
                body=body,
                topic=active_topic,
                push_type=push_type,
                priority=priority,
                expiration=expiration,
                collapse_id=collapse_id,
                extra_headers=extra_headers,
            )
            attempts += used
            tried.append(final_env)

        # —— 阶段三：provider token 失效 → 作废缓存并重签一次 ——
        if response.reason in (
            ApnsReason.EXPIRED_PROVIDER_TOKEN,
            ApnsReason.INVALID_PROVIDER_TOKEN,
        ):
            self._tokens.invalidate()
            response, used = self._attempt(
                environment=final_env,
                device_token=token_value,
                body=body,
                topic=active_topic,
                push_type=push_type,
                priority=priority,
                expiration=expiration,
                collapse_id=collapse_id,
                extra_headers=extra_headers,
            )
            attempts += used

        result = DeliveryResult(
            response=response,
            environment=final_env,
            fell_back=fell_back,
            attempts=attempts,
            tried=tuple(tried),
        )
        if raise_on_error and not result.ok:
            raise ApnsDeliveryError(result)
        return result

    def send_alert(
        self,
        device_token: str,
        title: str,
        body: str,
        *,
        badge: int = 0,
        sound: str = "default",
        custom_data: Optional[Mapping[str, Any]] = None,
        **kwargs: Any,
    ) -> DeliveryResult:
        """发送带 alert 的推送（对应源实现 ``send_alert``）。"""
        return self.send(
            device_token,
            build_alert_payload(
                title=title, body=body, badge=badge, sound=sound, custom_data=custom_data
            ),
            push_type="alert",
            **kwargs,
        )

    def send_many(
        self,
        device_tokens: Sequence[str],
        payload: Payload,
        **kwargs: Any,
    ) -> list[DeliveryResult]:
        """对多个设备令牌顺序发送；单个失败不影响后续。"""
        return [self.send(token, payload, **kwargs) for token in device_tokens]

    def close(self) -> None:
        """关闭底层传输。"""
        if self._owns_transport:
            self._transport.close()

    def __enter__(self) -> "ApnsClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ------------------------------------------------------------------ 内部实现

    def _encode_payload(self, payload: Payload) -> bytes:
        """序列化载荷并检查 4KB 上限。"""
        if not isinstance(payload, Mapping):
            raise ApnsConfigError(f"payload 必须是 dict，收到 {type(payload).__name__}")
        try:
            body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ApnsConfigError(f"payload 无法序列化为 JSON: {type(exc).__name__}") from exc

        if len(body) > MAX_PAYLOAD_BYTES:
            raise ApnsConfigError(
                f"payload 为 {len(body)} 字节，超过 APNs 上限 {MAX_PAYLOAD_BYTES} 字节"
            )
        return body

    def _build_headers(
        self,
        *,
        token: str,
        topic: str,
        push_type: str,
        priority: int,
        expiration: int | None,
        collapse_id: str | None,
        extra_headers: Mapping[str, str] | None,
    ) -> dict[str, str]:
        """组装请求头（键名与源实现一致，但统一小写成为 HTTP/2 规范形式）。"""
        headers: dict[str, str] = {
            "authorization": f"bearer {token}",
            "apns-topic": topic,
            "apns-push-type": push_type,
            "apns-priority": str(priority),
            "content-type": "application/json",
        }
        if expiration is not None:
            headers["apns-expiration"] = str(int(expiration))
        if collapse_id:
            headers["apns-collapse-id"] = str(collapse_id)

        headers.update(self.config.extra_headers)
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def _attempt(
        self,
        *,
        environment: ApnsEnvironment,
        device_token: str,
        body: bytes,
        topic: str,
        push_type: str,
        priority: int,
        expiration: int | None,
        collapse_id: str | None,
        extra_headers: Mapping[str, str] | None,
    ) -> tuple[ApnsResponse, int]:
        """在一个环境上发送，对可重试错误做指数退避。返回 ``(响应, 尝试次数)``。"""
        attempts = 0
        last: ApnsResponse | None = None

        for retry_index in range(self.config.max_retries + 1):
            attempts += 1

            # token 每条请求取一次；缓存命中时为零成本
            token = self._tokens.get()
            if not token:
                # 对齐源实现：拿不到 token 即失败
                return ApnsResponse(status=0, reason=ApnsReason.INVALID_PROVIDER_TOKEN), attempts

            headers = self._build_headers(
                token=token,
                topic=topic,
                push_type=push_type,
                priority=priority,
                expiration=expiration,
                collapse_id=collapse_id,
                extra_headers=extra_headers,
            )
            request = TransportRequest(
                method="POST",
                url=f"{environment.base_url}/3/device/{device_token}",
                headers=headers,
                body=body,
                timeout=self.config.timeout,
            )

            try:
                raw = self._transport.send(request)
            except ApnsTransportError as exc:
                last = ApnsResponse(
                    status=0,
                    reason=ApnsReason.SERVICE_UNAVAILABLE if exc.retryable else ApnsReason.UNKNOWN,
                )
                if not exc.retryable or retry_index >= self.config.max_retries:
                    return last, attempts
                self._backoff(retry_index)
                continue

            last = self._parse_response(raw)

            if last.ok or not last.retryable:
                return last, attempts
            if retry_index >= self.config.max_retries:
                return last, attempts
            self._backoff(retry_index)

        assert last is not None  # 循环至少执行一次
        return last, attempts

    def _parse_response(self, raw: TransportResponse) -> ApnsResponse:
        """把传输层响应解析成 :class:`ApnsResponse`。

        源实现只取 ``response.status_code`` 与 ``response.text``；这里额外解析
        Apple 的 ``reason`` 字段与 ``apns-id`` 响应头。
        """
        parsed: dict[str, Any] = {}
        reason: ApnsReason | None = None

        if raw.body:
            try:
                decoded = json.loads(raw.body.decode("utf-8"))
                if isinstance(decoded, dict):
                    parsed = decoded
                    reason = parse_reason(decoded.get("reason"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                # 非 JSON 响应体（例如网关返回 HTML）——保留状态码即可
                parsed = {}

        timestamp = parsed.get("timestamp")
        if not isinstance(timestamp, int):
            timestamp = None

        return ApnsResponse(
            status=raw.status,
            reason=reason,
            apns_id=raw.header("apns-id") or raw.header("x-apns-id"),
            timestamp=timestamp,
            body=parsed,
        )

    def _backoff(self, retry_index: int) -> None:
        """指数退避等待（源实现没有这一步，``max_retries=0`` 时不会触发）。"""
        delay = self.config.retry_backoff * (2**retry_index)
        delay += self._jitter(delay)
        if delay > 0:
            self._sleep(delay)
