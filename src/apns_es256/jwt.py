"""ES256 provider token 的组装与签名（抽取自源实现的 ``_generate_token``）。

抽取与改写说明
--------------
源实现把 JWT 组装、私钥读取、DER→R‖S 转换全部内联在一个方法里，并用
``except Exception`` 兜住一切、失败返回 ``None``。本模块做如下拆分与改写：

1. **日志脱敏**：源实现用 ``logging.getLogger("<内部项目名>_push")`` 并打印异常文本；
   本库**不主动打日志**，改为抛出结构化异常，避免库污染调用方日志树、
   也避免异常文本里意外带出敏感路径。
2. **并发安全**：源实现的 ``self._token``/``self._token_expire`` 缓存没有加锁；
   本库加 ``threading.Lock``（Web 服务多线程下源实现可能重复签名，
   而 Apple 对重签频率有限制 ``TooManyProviderTokenUpdates``）。
3. **DER→R‖S** 移到 :mod:`apns_es256.der`，改为纯标准库实现。

两者行为一致的要点：token 缓存 **3600 秒、提前 60 秒失效**；claims 含
``iss``/``iat``/``exp``；header 为 ``{"alg":"ES256","kid":<KeyID>}``。

动机：为什么不用 PyJWT
--------------------
这正是源实现注释里写明的成因——``PyJWT`` 的 ``crypto`` extra 对 ``cryptography``
版本有较紧约束；当运行环境的 ``cryptography`` 由系统包管理器提供、或已被其它依赖
钉死时，``pip install "pyjwt[crypto]"`` 会强制升降级甚至报版本冲突，从而波及同环境
所有 TLS/证书/加密调用。而 APNs provider token 本身只是一个固定头 + 固定载荷 +
一次 ``ECDSA-P256-SHA256`` 签名，直接手写即可，不必让一个第三方 JWT 库参与版本求解。
"""

from __future__ import annotations

import base64
import json
import threading
import time
from pathlib import Path
from typing import Optional

from .der import der_to_raw
from .errors import ApnsAuthError, ApnsConfigError

#: 源实现写死的 token 有效期（秒）。Apple 规定上限 1 小时。
DEFAULT_TOKEN_TTL = 3600

#: 源实现写死的提前失效余量（秒）：``time.time() < expire - 60``。
DEFAULT_TOKEN_SAFETY_MARGIN = 60

#: JWA 算法名。
_ALG = "ES256"


def b64url(raw: bytes) -> str:
    """RFC 7515 的 base64url：无填充、``-``/``_`` 代替 ``+``/``/``。

    等价于源实现内联的 ``_b64()``。
    """
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _json_segment(payload: dict) -> str:
    """紧凑 JSON + base64url。

    源实现用 ``json.dumps(obj, separators=(',', ':'))``（不排序键）；这里额外
    ``sort_keys=True``，使同一份 claims 产生稳定字节序列，便于测试与缓存比对。
    """
    return b64url(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )


def load_private_key(key_path: str | Path) -> object:
    """从 ``.p8`` 文件加载 EC P-256 私钥。

    对应源实现的 ``serialization.load_pem_private_key(auth_key, password=None,
    backend=default_backend())``，但额外断言曲线必须是 P-256 ——
    源实现未校验，若误配 P-384 密钥会在 Apple 侧才以 403 暴露。
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as exc:  # pragma: no cover - 取决于环境
        raise ApnsAuthError("需要 cryptography 才能加载 .p8 私钥") from exc

    path = Path(key_path)
    if not path.is_file():
        raise ApnsConfigError(f"私钥文件不存在: {path}")

    try:
        key_pem = path.read_bytes()
    except OSError as exc:
        raise ApnsConfigError(f"私钥文件读取失败: {path}") from exc

    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except Exception as exc:  # noqa: BLE001 - 统一转成本库异常
        # 注意：不回显异常原文，避免把文件路径/内容片段带进错误信息
        raise ApnsConfigError(
            f"私钥解析失败（应为 PKCS#8 PEM 格式的 EC P-256 密钥）: {type(exc).__name__}"
        ) from exc

    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise ApnsConfigError("私钥不是 EC 私钥，APNs ES256 需要 EC P-256")
    if not isinstance(key.curve, ec.SECP256R1):
        raise ApnsConfigError(
            f"APNs ES256 要求 P-256(SECP256R1)，当前私钥曲线为 {key.curve.name}"
        )
    return key


def build_jwt(
    *,
    key_id: str,
    team_id: str,
    key_path: str | Path | None = None,
    private_key: object | None = None,
    issued_at: Optional[int] = None,
    ttl: int = DEFAULT_TOKEN_TTL,
) -> str:
    """组装并签名一个 APNs provider token。

    与源实现 ``_generate_token()`` 的产出一致（同样的 header/claims/签名格式）。

    :param key_id: Apple Developer Key ID。
    :param team_id: Apple Developer Team ID。
    :param key_path: ``.p8`` 路径；与 ``private_key`` 二选一。
    :param private_key: 已加载的 ``cryptography`` 私钥对象（测试可注入）。
    :param issued_at: ``iat`` 秒级时间戳，默认当前时间。
    :param ttl: ``exp`` 相对 ``iat`` 的秒数（源实现为 3600）。
    """
    if not key_id or not key_id.strip():
        raise ApnsConfigError("key_id 不能为空")
    if not team_id or not team_id.strip():
        raise ApnsConfigError("team_id 不能为空")
    if private_key is None and key_path is None:
        raise ApnsConfigError("必须提供 key_path 或 private_key")

    if private_key is None:
        private_key = load_private_key(key_path)  # type: ignore[arg-type]

    iat = int(time.time()) if issued_at is None else int(issued_at)

    header = {"alg": _ALG, "kid": key_id.strip()}
    claims = {"iss": team_id.strip(), "iat": iat, "exp": iat + max(1, int(ttl))}

    signing_input = f"{_json_segment(header)}.{_json_segment(claims)}".encode("ascii")

    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as exc:  # pragma: no cover
        raise ApnsAuthError("需要 cryptography 才能执行 ES256 签名") from exc

    try:
        der_signature = private_key.sign(  # type: ignore[attr-defined]
            signing_input, ec.ECDSA(hashes.SHA256())
        )
    except AttributeError as exc:
        raise ApnsAuthError(f"私钥对象不支持 sign(): {type(private_key)!r}") from exc
    except Exception as exc:  # noqa: BLE001
        raise ApnsAuthError(f"ES256 签名失败: {type(exc).__name__}") from exc

    # 源实现: r, s = decode_dss_signature(der_sig); raw = r.to_bytes(32,'big')+s.to_bytes(32,'big')
    raw_signature = der_to_raw(der_signature, "P-256")

    return f"{signing_input.decode('ascii')}.{b64url(raw_signature)}"


class TokenProvider:
    """带缓存的 provider token 生成器，线程安全。

    忠实复刻源实现的缓存语义：``self._token`` / ``self._token_expire``，判定条件是
    ``time.time() < expire - 60``，有效期 3600 秒。差别仅是加了锁。
    """

    def __init__(
        self,
        *,
        key_id: str,
        team_id: str,
        key_path: str | Path | None = None,
        private_key: object | None = None,
        ttl: int = DEFAULT_TOKEN_TTL,
        safety_margin: int = DEFAULT_TOKEN_SAFETY_MARGIN,
        clock=time.time,
    ) -> None:
        self._key_id = key_id
        self._team_id = team_id
        self._ttl = max(1, int(ttl))
        self._safety_margin = max(0, int(safety_margin))
        self._clock = clock
        self._lock = threading.Lock()

        # 私钥只加载一次（源实现每次重签都重新读盘 + 重新解析 PEM）
        if private_key is None:
            if key_path is None:
                raise ApnsConfigError("必须提供 key_path 或 private_key")
            private_key = load_private_key(key_path)
        self._private_key = private_key

        self._token: Optional[str] = None
        self._token_expire: Optional[float] = None

    def __call__(self) -> Optional[str]:
        return self.get()

    def get(self) -> Optional[str]:
        """返回有效 token；缓存命中则直接复用。

        与源实现一致：**签名失败时返回 None**（源实现是 ``except`` 后 return None），
        由调用方判断。若希望改成抛异常语义，用 :meth:`get_or_raise`。
        """
        now = self._clock()
        with self._lock:
            if (
                self._token
                and self._token_expire
                and now < self._token_expire - self._safety_margin
            ):
                return self._token
            try:
                token = build_jwt(
                    key_id=self._key_id,
                    team_id=self._team_id,
                    private_key=self._private_key,
                    issued_at=int(now),
                    ttl=self._ttl,
                )
            except (ApnsConfigError, ApnsAuthError):
                return None
            self._token = token
            self._token_expire = now + self._ttl
            return token

    def get_or_raise(self) -> str:
        """同 :meth:`get`，但失败时抛出异常（本库客户端默认用这个）。"""
        now = self._clock()
        with self._lock:
            if (
                self._token
                and self._token_expire
                and now < self._token_expire - self._safety_margin
            ):
                return self._token
            token = build_jwt(
                key_id=self._key_id,
                team_id=self._team_id,
                private_key=self._private_key,
                issued_at=int(now),
                ttl=self._ttl,
            )
            self._token = token
            self._token_expire = now + self._ttl
            return token

    def invalidate(self) -> None:
        """丢弃缓存，强制下次重签（收到 token 失效类错误时调用）。"""
        with self._lock:
            self._token = None
            self._token_expire = None
