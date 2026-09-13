"""端到端冒烟测试：以「外部使用者」视角调用公开 API（完全离线）。

目的是验证 README 里的用法示例真的能跑，而不是只有单元测试通过。
所有网络交互都被 StubTransport 替代，不会访问 Apple。
"""

from __future__ import annotations

import json

from apns_es256 import (
    ApnsClient,
    ApnsConfig,
    ApnsEnvironment,
    ApnsReason,
    der_to_raw,
    raw_to_der,
)
from apns_es256.transport import TransportRequest, TransportResponse

from _stubs import FAKE_BUNDLE_ID, FAKE_DEVICE_TOKEN, StaticTokenProvider

cryptography = __import__("pytest").importorskip("cryptography")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402


class RecordingTransport:
    """按 host 返回不同响应的假传输层：生产回 BadDeviceToken，沙箱回 200。"""

    def __init__(self) -> None:
        self.requests: list[TransportRequest] = []

    def send(self, request: TransportRequest) -> TransportResponse:
        self.requests.append(request)
        if "sandbox" in request.url:
            return TransportResponse(
                status=200, headers={"apns-id": "sandbox-ok"}, body=b""
            )
        return TransportResponse(
            status=400,
            headers={},
            body=json.dumps({"reason": "BadDeviceToken"}).encode(),
        )

    def close(self) -> None:  # pragma: no cover
        pass


def test_readme_usage_end_to_end(tmp_path) -> None:
    """完整走一遍 README「最小用法」：真密钥 → 签名 → 生产回落 → 沙箱成功。"""
    # 1) 生成一次性测试私钥（非任何真实凭据）
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_file = tmp_path / "AuthKey_PLACEHOLDER.p8"
    key_file.write_bytes(pem)

    # 2) 用真实私钥构造 provider（走真 cryptography 签名路径）
    from apns_es256 import make_token_provider

    provider = make_token_provider(
        key_id="ABCDE12345", team_id="ZYXWV98765", key_path=key_file
    )

    # 3) 配置 + 客户端
    config = ApnsConfig(
        key_id="ABCDE12345",
        team_id="ZYXWV98765",
        bundle_id=FAKE_BUNDLE_ID,
        key_path=str(key_file),
        environment=ApnsEnvironment.PRODUCTION,
    )
    transport = RecordingTransport()
    with ApnsClient(config, transport=transport, token_provider=provider) as client:
        result = client.send(
            device_token=FAKE_DEVICE_TOKEN,
            payload={"aps": {"alert": "你好", "sound": "default", "badge": 1}},
        )

    # 4) 断言：确实回落了，并且沙箱成功
    assert result.ok, f"应成功，实际 {result.response.status} {result.response.reason}"
    assert result.fell_back is True
    assert result.apns_id == "sandbox-ok"
    assert result.tried == (ApnsEnvironment.PRODUCTION, ApnsEnvironment.SANDBOX)

    # 两次请求：生产 + 沙箱
    assert len(transport.requests) == 2
    assert "api.push.apple.com" in transport.requests[0].url
    assert "api.sandbox.push.apple.com" in transport.requests[1].url

    # 5) 验证 authorization 头里是一个真正的、可验签的 ES256 JWT
    auth = transport.requests[0].headers["authorization"]
    assert auth.startswith("bearer ")
    token = auth.removeprefix("bearer ")
    header_b64, claims_b64, sig_b64 = token.split(".")

    import base64

    def _dec(seg: str) -> dict:
        return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))

    assert _dec(header_b64)["alg"] == "ES256"
    assert _dec(header_b64)["kid"] == "ABCDE12345"
    assert _dec(claims_b64)["iss"] == "ZYXWV98765"

    raw_sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    assert len(raw_sig) == 64, "JWT 签名必须是 64 字节原始 R‖S"

    # 用公钥独立验签 —— 证明 DER→R‖S 转换正确
    key.public_key().verify(
        raw_to_der(raw_sig),
        f"{header_b64}.{claims_b64}".encode("ascii"),
        ec.ECDSA(hashes.SHA256()),
    )

    # 6) 载荷原样送达且为紧凑 JSON
    body = json.loads(transport.requests[0].body)
    assert body == {"aps": {"alert": "你好", "sound": "default", "badge": 1}}
    assert "你好".encode("utf-8") in transport.requests[0].body


def test_der_helpers_public_api() -> None:
    """公开 API 的 DER 工具可直接用于外部代码。"""
    r = bytes([0x80]) + b"\x11" * 31
    s = bytes([0x22]) * 32
    body = (
        b"\x02\x21\x00"
        + r
        + b"\x02\x20"
        + s
    )
    der = b"\x30" + bytes([len(body)]) + body
    raw = der_to_raw(der)
    assert raw == r + s
    assert raw_to_der(raw) == der


def test_reason_callback_end_to_end(tmp_path) -> None:
    """验证 UNREGISTERED 回调可在真实使用姿势下触发（用于清理失效令牌）。"""
    dropped: list[str] = []

    class GoneTransport:
        def send(self, request: TransportRequest) -> TransportResponse:
            return TransportResponse(
                status=410,
                headers={},
                body=json.dumps({"reason": "Unregistered", "timestamp": 1}).encode(),
            )

        def close(self) -> None:  # pragma: no cover
            pass

    config = ApnsConfig(
        key_id="ABCDE12345",
        team_id="ZYXWV98765",
        bundle_id=FAKE_BUNDLE_ID,
        key_pem="placeholder",
    )
    client = ApnsClient(
        config,
        transport=GoneTransport(),
        token_provider=StaticTokenProvider(),
        on_reason={ApnsReason.UNREGISTERED: lambda r: dropped.append("x")},
    )
    result = client.send(device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}})

    assert not result.ok
    assert result.response.reason is ApnsReason.UNREGISTERED
    assert dropped == ["x"], "回调必须被触发，以便调用方清理失效令牌"
