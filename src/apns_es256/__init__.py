"""apns-es256 —— 一个小而专注的 APNs 直连推送库。

手写 ES256 provider token（含 DER → 原始 R‖S 转换），HTTP/2 直连
``api.push.apple.com``，生产端点遇 ``BadDeviceToken`` 自动回落沙箱。

不依赖 PyJWT：避开 PyJWT 与系统 ``cryptography`` 的版本约束冲突。
抽取来源与改写记录见 ``EXTRACT-PLAN.md``。
"""

from __future__ import annotations

from .client import (
    MAX_PAYLOAD_BYTES,
    ApnsClient,
    DeliveryResult,
    build_alert_payload,
    validate_device_token,
)
from .config import (
    ENV_BUNDLE_ID,
    ENV_KEY_ID,
    ENV_KEY_PATH,
    ENV_TEAM_ID,
    PRODUCTION_HOST,
    SANDBOX_HOST,
    ApnsConfig,
    ApnsEnvironment,
)
from .der import (
    DerError,
    der_to_raw,
    join_raw,
    raw_to_der,
    signature_size,
    split_raw,
)
from .errors import (
    ApnsAuthError,
    ApnsConfigError,
    ApnsDeliveryError,
    ApnsError,
    ApnsReason,
    ApnsResponse,
    ApnsTransportError,
    ErrorClass,
    classify,
    parse_reason,
)
from .jwt import (
    DEFAULT_TOKEN_SAFETY_MARGIN,
    DEFAULT_TOKEN_TTL,
    TokenProvider,
    b64url,
    build_jwt,
    load_private_key,
)
from .transport import (
    HttpxTransport,
    Transport,
    TransportRequest,
    TransportResponse,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # 客户端
    "ApnsClient",
    "ApnsConfig",
    "ApnsEnvironment",
    "DeliveryResult",
    "build_alert_payload",
    "validate_device_token",
    "MAX_PAYLOAD_BYTES",
    # 端点与环境变量名
    "PRODUCTION_HOST",
    "SANDBOX_HOST",
    "ENV_KEY_ID",
    "ENV_TEAM_ID",
    "ENV_BUNDLE_ID",
    "ENV_KEY_PATH",
    # DER / R‖S
    "der_to_raw",
    "raw_to_der",
    "signature_size",
    "split_raw",
    "join_raw",
    "DerError",
    # JWT
    "build_jwt",
    "load_private_key",
    "b64url",
    "TokenProvider",
    "DEFAULT_TOKEN_TTL",
    "DEFAULT_TOKEN_SAFETY_MARGIN",
    # 错误
    "ApnsError",
    "ApnsConfigError",
    "ApnsAuthError",
    "ApnsDeliveryError",
    "ApnsTransportError",
    "ApnsReason",
    "ApnsResponse",
    "ErrorClass",
    "classify",
    "parse_reason",
    # 传输层
    "Transport",
    "TransportRequest",
    "TransportResponse",
    "HttpxTransport",
]
