"""测试专用的假对象与常量。

**本模块只包含占位符**：所有凭据类字符串（KeyID / TeamID / bundle id / 设备令牌）
都是明显虚假的值，与任何真实账号无关。

另有一个辅助函数 :func:`make_test_key` 在**运行时即时生成**一次性 EC P-256 私钥；
测试从不使用、也从不复制任何真实 ``.p8`` 文件。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# 让测试在未做 `pip install -e .` 的情况下也能直接跑（源码布局 src/）
_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from apns_es256 import ApnsConfig, ApnsEnvironment  # noqa: E402
from apns_es256.transport import (  # noqa: E402
    Transport,
    TransportRequest,
    TransportResponse,
)

#: 测试用的假凭据 —— 全部是占位符，与任何真实账号无关。
FAKE_KEY_ID = "ABCDE12345"
FAKE_TEAM_ID = "ZYXWV98765"
FAKE_BUNDLE_ID = "com.example.app"

#: 合法的 64 位十六进制设备令牌（占位）。
FAKE_DEVICE_TOKEN = "0f1e2d3c4b5a69788796a5b4c3d2e1f0" * 2


class StubTransport:
    """记录请求并返回预设响应的测试替身。

    这是本套件"不联网"的根本保证：客户端只会调用这个对象，永远不碰 socket。
    """

    def __init__(self, scripted: list[TransportResponse] | None = None) -> None:
        #: 按顺序弹出预设响应；用尽后重复最后一个（为空则默认 200）
        self._scripted = list(scripted or [])
        self.requests: list[TransportRequest] = []
        self.closed = False

    def send(self, request: TransportRequest) -> TransportResponse:
        self.requests.append(request)
        if not self._scripted:
            return TransportResponse(status=200, headers={"apns-id": "stub-id"}, body=b"")
        if len(self._scripted) == 1:
            return self._scripted[0]
        return self._scripted.pop(0)

    def close(self) -> None:
        self.closed = True

    # —— 断言辅助 ——

    @property
    def urls(self) -> list[str]:
        return [r.url for r in self.requests]

    @property
    def last_headers(self) -> dict[str, str]:
        return dict(self.requests[-1].headers)

    def last_body(self) -> object:
        return json.loads(self.requests[-1].body.decode("utf-8"))


def assert_is_transport(obj: object) -> None:
    """静态确认某个对象满足 Transport 协议。"""
    assert isinstance(obj, Transport)


def make_response(
    status: int,
    reason: str | None = None,
    *,
    apns_id: str | None = None,
    timestamp: int | None = None,
) -> TransportResponse:
    """构造一个 APNs 风格的传输层响应。"""
    body: dict[str, object] = {}
    if reason is not None:
        body["reason"] = reason
    if timestamp is not None:
        body["timestamp"] = timestamp

    headers: dict[str, str] = {}
    if apns_id is not None:
        headers["apns-id"] = apns_id

    return TransportResponse(
        status=status,
        headers=headers,
        body=json.dumps(body).encode("utf-8") if body else b"",
    )


class StaticTokenProvider:
    """返回固定 token 的 provider，用于完全不触碰 cryptography 的测试。

    与 :class:`apns_es256.TokenProvider` 接口兼容（``get`` / ``invalidate``）。
    """

    def __init__(self, token: str | None = "stub.token.value") -> None:
        self._token = token
        self.invalidations = 0
        self.calls = 0

    def __call__(self) -> str | None:
        return self.get()

    def get(self) -> str | None:
        self.calls += 1
        return self._token

    def get_or_raise(self) -> str:
        token = self.get()
        if not token:
            raise AssertionError("stub token 为空")
        return token

    def invalidate(self) -> None:
        self.invalidations += 1


def make_test_key(tmp_path: Path, filename: str = "AuthKey_PLACEHOLDER.p8"):
    """运行时即时生成一次性 EC P-256 私钥并写入临时文件。

    返回 ``(private_key, p8_path)``。**不读取任何真实密钥文件。**
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path = tmp_path / filename
    path.write_bytes(pem)
    return key, path


def make_config(key_path: Path, **overrides: object) -> ApnsConfig:
    """用假凭据 + 临时密钥文件构造配置。"""
    values: dict[str, object] = {
        "key_id": FAKE_KEY_ID,
        "team_id": FAKE_TEAM_ID,
        "bundle_id": FAKE_BUNDLE_ID,
        "key_path": str(key_path),
        "environment": ApnsEnvironment.PRODUCTION,
    }
    values.update(overrides)
    return ApnsConfig(**values)  # type: ignore[arg-type]
