"""APNs 响应解析、错误分类与重试语义。

APNs 用 HTTP 状态码 + JSON body 里的 ``reason`` 字符串表达失败原因。本模块把
裸字符串收敛成枚举并给出**是否可重试**的判断，让客户端不必到处散落魔法字符串。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class ApnsReason(str, Enum):
    """APNs 文档中出现的 ``reason`` 值。"""

    # —— 设备令牌类 ——
    BAD_DEVICE_TOKEN = "BadDeviceToken"
    DEVICE_TOKEN_NOT_FOR_TOPIC = "DeviceTokenNotForTopic"
    UNREGISTERED = "Unregistered"

    # —— 请求头 / 认证类 ——
    BAD_COLLAPSE_ID = "BadCollapseId"
    BAD_EXPIRATION_DATE = "BadExpirationDate"
    BAD_MESSAGE_ID = "BadMessageId"
    BAD_PRIORITY = "BadPriority"
    BAD_TOPIC = "BadTopic"
    INVALID_PUSH_TYPE = "InvalidPushType"
    MISSING_TOPIC = "MissingTopic"
    TOPIC_DISALLOWED = "TopicDisallowed"
    INVALID_PROVIDER_TOKEN = "InvalidProviderToken"
    MISSING_PROVIDER_TOKEN = "MissingProviderToken"
    EXPIRED_PROVIDER_TOKEN = "ExpiredProviderToken"

    # —— 载荷类 ——
    BAD_MESSAGE = "BadMessage"
    PAYLOAD_EMPTY = "PayloadEmpty"
    PAYLOAD_TOO_LARGE = "PayloadTooLarge"
    BAD_PATH = "BadPath"
    METHOD_NOT_ALLOWED = "MethodNotAllowed"
    UNSUPPORTED_TIME = "UnsupportedTime"
    MISSING_DEVICE_TOKEN = "MissingDeviceToken"
    TOPIC_MISMATCH = "TopicMismatch"

    # —— 限流 / 服务端 ——
    TOO_MANY_PROVIDER_TOKEN_REQUESTS = "TooManyProviderTokenUpdates"
    TOO_MANY_REQUESTS = "TooManyRequests"
    INTERNAL_SERVER_ERROR = "InternalServerError"
    SERVICE_UNAVAILABLE = "ServiceUnavailable"
    SHUTDOWN = "Shutdown"

    # —— 其它 ——
    DUPLICATE_HEADERS = "DuplicateHeaders"
    IDLE_TIMEOUT = "IdleTimeout"
    UNKNOWN = "Unknown"


class ErrorClass(str, Enum):
    """把失败原因归成调用方真正关心的几类处置动作。"""

    #: 设备令牌无效/过期 —— 应从数据库清除，不要重试。
    UNREGISTERED = "unregistered"
    #: 令牌与当前环境或 topic 不匹配 —— 可能换环境重试（沙箱回落）。
    TOKEN_MISMATCH = "token_mismatch"
    #: provider token（JWT）有问题 —— 需要重新签名后重试。
    AUTH = "auth"
    #: 请求本身不合法 —— 改代码，不要重试。
    BAD_REQUEST = "bad_request"
    #: 暂时性故障 —— 可退避重试。
    RETRYABLE = "retryable"
    #: 限流 —— 可退避重试，但要放慢。
    THROTTLED = "throttled"
    #: 未知。
    UNKNOWN = "unknown"


#: reason → 分类
_REASON_CLASS: dict[ApnsReason, ErrorClass] = {
    ApnsReason.BAD_DEVICE_TOKEN: ErrorClass.TOKEN_MISMATCH,
    ApnsReason.DEVICE_TOKEN_NOT_FOR_TOPIC: ErrorClass.TOKEN_MISMATCH,
    ApnsReason.UNREGISTERED: ErrorClass.UNREGISTERED,
    ApnsReason.BAD_COLLAPSE_ID: ErrorClass.BAD_REQUEST,
    ApnsReason.BAD_EXPIRATION_DATE: ErrorClass.BAD_REQUEST,
    ApnsReason.BAD_MESSAGE_ID: ErrorClass.BAD_REQUEST,
    ApnsReason.BAD_PRIORITY: ErrorClass.BAD_REQUEST,
    ApnsReason.BAD_TOPIC: ErrorClass.BAD_REQUEST,
    ApnsReason.INVALID_PUSH_TYPE: ErrorClass.BAD_REQUEST,
    ApnsReason.MISSING_TOPIC: ErrorClass.BAD_REQUEST,
    ApnsReason.TOPIC_DISALLOWED: ErrorClass.BAD_REQUEST,
    ApnsReason.INVALID_PROVIDER_TOKEN: ErrorClass.AUTH,
    ApnsReason.MISSING_PROVIDER_TOKEN: ErrorClass.AUTH,
    ApnsReason.EXPIRED_PROVIDER_TOKEN: ErrorClass.AUTH,
    ApnsReason.BAD_MESSAGE: ErrorClass.BAD_REQUEST,
    ApnsReason.PAYLOAD_EMPTY: ErrorClass.BAD_REQUEST,
    ApnsReason.PAYLOAD_TOO_LARGE: ErrorClass.BAD_REQUEST,
    ApnsReason.BAD_PATH: ErrorClass.BAD_REQUEST,
    ApnsReason.METHOD_NOT_ALLOWED: ErrorClass.BAD_REQUEST,
    ApnsReason.UNSUPPORTED_TIME: ErrorClass.BAD_REQUEST,
    ApnsReason.MISSING_DEVICE_TOKEN: ErrorClass.BAD_REQUEST,
    ApnsReason.TOPIC_MISMATCH: ErrorClass.TOKEN_MISMATCH,
    ApnsReason.TOO_MANY_PROVIDER_TOKEN_REQUESTS: ErrorClass.THROTTLED,
    ApnsReason.TOO_MANY_REQUESTS: ErrorClass.THROTTLED,
    ApnsReason.INTERNAL_SERVER_ERROR: ErrorClass.RETRYABLE,
    ApnsReason.SERVICE_UNAVAILABLE: ErrorClass.RETRYABLE,
    ApnsReason.SHUTDOWN: ErrorClass.RETRYABLE,
    ApnsReason.DUPLICATE_HEADERS: ErrorClass.BAD_REQUEST,
    ApnsReason.IDLE_TIMEOUT: ErrorClass.RETRYABLE,
    ApnsReason.UNKNOWN: ErrorClass.UNKNOWN,
}

#: 可以安全重试的分类
RETRYABLE_CLASSES = frozenset(
    {ErrorClass.RETRYABLE, ErrorClass.THROTTLED}
)


def parse_reason(value: str | None) -> ApnsReason | None:
    """把 APNs 返回的 reason 字符串解析为枚举，未知值归为 ``UNKNOWN``。

    ``None``/空字符串返回 ``None``（表示没有 reason，通常意味着成功）。
    """
    if value is None:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        return ApnsReason(text)
    except ValueError:
        return ApnsReason.UNKNOWN


def classify(reason: ApnsReason | str | None) -> ErrorClass:
    """判断某个 reason 的处置分类。``None`` 视为成功 → ``UNKNOWN``。"""
    if reason is None:
        return ErrorClass.UNKNOWN
    if isinstance(reason, str):
        reason = parse_reason(reason)
    if reason is None:  # pragma: no cover - 防御
        return ErrorClass.UNKNOWN
    return _REASON_CLASS.get(reason, ErrorClass.UNKNOWN)


@dataclass(frozen=True)
class ApnsResponse:
    """一次 APNs 调用结果的规范化视图。"""

    status: int
    reason: ApnsReason | None = None
    #: ``apns-id`` / ``x-apns-id`` 响应头，排障时用来找 Apple 侧日志。
    apns_id: str | None = None
    #: ``Unregistered`` 或 ``410`` 时返回，提示令牌失效时间戳。
    timestamp: int | None = None
    #: 原始响应体，保留给需要看未解析字段的调用方。
    body: Mapping[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """HTTP 200 且无 reason 才算成功。"""
        return self.status == 200 and self.reason is None

    @property
    def error_class(self) -> ErrorClass:
        """本次结果的处置分类。"""
        if self.ok:
            return ErrorClass.UNKNOWN
        if self.reason is not None:
            return classify(self.reason)
        # 没有 reason 时退化为按状态码判断
        if self.status in (500, 502, 503, 504):
            return ErrorClass.RETRYABLE
        if self.status == 429:
            return ErrorClass.THROTTLED
        if self.status == 403:
            return ErrorClass.AUTH
        if self.status == 400:
            return ErrorClass.BAD_REQUEST
        if self.status == 410:
            return ErrorClass.UNREGISTERED
        return ErrorClass.UNKNOWN

    @property
    def retryable(self) -> bool:
        """重试是否可能成功（基于分类，不含沙箱回落这种特殊策略）。"""
        return self.error_class in RETRYABLE_CLASSES


class ApnsError(Exception):
    """本库所有异常的基类。"""


class ApnsConfigError(ApnsError):
    """配置缺失或非法（例如没给 KeyID、TeamID，或私钥读取失败）。"""


class ApnsAuthError(ApnsError):
    """provider token 签名相关失败。"""


class ApnsTransportError(ApnsError):
    """网络层失败：连接、超时、HTTP/2 协商等。"""

    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


class ApnsDeliveryError(ApnsError):
    """APNs 明确拒绝了这次推送（带结构化响应）。

    客户端默认返回 :class:`DeliveryResult` 而不抛这个异常；当调用方设置
    ``raise_on_error=True`` 时会抛出，便于 "失败即中断" 的批处理场景。
    """

    def __init__(self, result: "DeliveryResult") -> None:  # noqa: F821
        self.result = result
        reason = result.response.reason.value if result.response.reason else None
        super().__init__(
            f"APNs 拒绝了推送: status={result.response.status}"
            + (f" reason={reason}" if reason else "")
        )
