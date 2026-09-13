"""端到端冒烟测试：以「外部使用者」视角调用公开 API（完全离线）。

目的是验证 README 里的用法示例真的能跑，而不是只有单元测试通过。
所有网络交互都被 stub 传输层替代，不会访问 Apple。
"""

from __future__ import annotations

import base64
import json

from apns_es256 import (
    ApnsClient,
    ApnsConfig,
    ApnsEnvironment,
    ApnsReason,
    TokenProvider,
    der_to_raw,
    raw_to_der,
)
from apns_es256.transport import TransportRequest, TransportResponse

from _stubs import FAKE_BUNDLE_ID, FAKE_DEVICE_TOKEN, make_test_key

cryptography = __import__("pytest").importorskip("cryptography")

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402


class RecordingTransport:
    """按 host 返回不同响应：生产回 BadDeviceToken，沙箱回 200。"""

    def __init__(self) -> None:
        self.requests: list[TransportRequest] = []

    def send(self, request: TransportRequest) -> TransportResponse:
        self.requests.append(request)
        if "sandbox" in request.url:
            return TransportResponse(status=200, headers={"apns-id": "sandbox-ok"}, body=b"")
        return TransportResponse(
            status=400, headers={}, body=json.dumps({"reason": "BadDeviceToken"}).encode()
        )

    def close(self) -> None:  # pragma: no cover
        pass


def _dec(seg: str) -> dict:
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


def test_readme_usage_end_to_end(tmp_path) -> None:
    """走一遍 README「最小用法」：真密钥 → 签名 → 生产回落 → 沙箱成功。"""
    # 1) 运行时生成一次性测试私钥（非任何真实凭据）
    key, key_file = make_test_key(tmp_path)

    # 2) 真实私钥构造 provider（走真 cryptography 签名路径）
    provider = TokenProvider(
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
            FAKE_DEVICE_TOKEN,
            {"aps": {"alert": "你好", "sound": "default", "badge": 1}},
        )

    # 4) 确实回落了，并且沙箱成功
    assert result.ok, f"应成功，实际 {result.status_code} {result.response.reason}"
    assert result.fell_back is True
    assert result.apns_id == "sandbox-ok"
    assert result.tried == (ApnsEnvironment.PRODUCTION, ApnsEnvironment.SANDBOX)

    # 两次请求：生产 + 沙箱
    assert len(transport.requests) == 2
    assert "api.push.apple.com" in transport.requests[0].url
    assert "api.sandbox.push.apple.com" in transport.requests[1].url

    # 5) authorization 头里是真正的、可验签的 ES256 JWT
    auth = transport.requests[0].headers["authorization"]
    assert auth.startswith("bearer ")
    header_b64, claims_b64, sig_b64 = auth.removeprefix("bearer ").split(".")

    assert _dec(header_b64)["alg"] == "ES256"
    assert _dec(header_b64)["kid"] == "ABCDE12345"
    assert _dec(claims_b64)["iss"] == "ZYXWV98765"

    raw_sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
    assert len(raw_sig) == 64, "JWT 签名必须是 64 字节原始 R‖S"

    key.public_key().verify(
        raw_to_der(raw_sig),
        f"{header_b64}.{claims_b64}".encode("ascii"),
        ec.ECDSA(hashes.SHA256()),
    )

    # 6) 载荷原样送达
    assert json.loads(transport.requests[0].body) == {
        "aps": {"alert": "你好", "sound": "default", "badge": 1}
    }


def test_send_alert_end_to_end(tmp_path) -> None:
    """send_alert 全链路（对应源实现 APNsService.send_alert）。"""
    _, key_file = make_test_key(tmp_path)
    config = ApnsConfig(
        key_id="ABCDE12345",
        team_id="ZYXWV98765",
        bundle_id=FAKE_BUNDLE_ID,
        key_path=str(key_file),
    )
    transport = RecordingTransport()
    with ApnsClient(config, transport=transport) as client:
        result = client.send_alert(FAKE_DEVICE_TOKEN, "标题", "正文", badge=2)

    assert result.ok and result.fell_back is True
    body = json.loads(transport.requests[0].body)
    assert body["aps"]["alert"] == {"title": "标题", "body": "正文"}
    assert body["aps"]["badge"] == 2


def test_extraction_matches_source_signature_format(tmp_path) -> None:
    """端到端证明抽取的 DER→R‖S 与源实现写法结果一致。"""
    key, _ = make_test_key(tmp_path)
    signing_input = b"probe"
    der_sig = key.sign(signing_input, ec.ECDSA(hashes.SHA256()))

    # 源实现写法
    r, s = utils.decode_dss_signature(der_sig)
    assert der_to_raw(der_sig) == r.to_bytes(32, "big") + s.to_bytes(32, "big")


def test_unregistered_flow(tmp_path) -> None:
    """410 Unregistered 端到端：应判定为需删除令牌，且不回落。"""

    class Gone:
        def send(self, request: TransportRequest) -> TransportResponse:
            return TransportResponse(
                status=410,
                headers={},
                body=json.dumps({"reason": "Unregistered", "timestamp": 1}).encode(),
            )

        def close(self) -> None:  # pragma: no cover
            pass

    _, key_file = make_test_key(tmp_path)
    config = ApnsConfig(
        key_id="ABCDE12345",
        team_id="ZYXWV98765",
        bundle_id=FAKE_BUNDLE_ID,
        key_path=str(key_file),
    )
    with ApnsClient(config, transport=Gone()) as client:
        result = client.send(FAKE_DEVICE_TOKEN, {"aps": {}})

    assert not result.ok
    assert result.response.reason is ApnsReason.UNREGISTERED
    assert result.fell_back is False
    # 迁移兼容：字典形状与源实现一致
    assert result.as_dict()["status_code"] == 410
    assert result.as_dict()["error"] == "Unregistered"
