"""ES256 provider token 的测试。

这里用**测试内部即时生成**的 EC P-256 密钥 —— 不涉及任何真实凭据。
最重要的一条是 :class:`TestRealCryptography`：用真 cryptography 签一次，
再用公钥验签，从而独立证明 DER→R‖S 转换确实产生了合法签名。
"""

from __future__ import annotations

import base64
import json

import pytest

from apns_es256 import (
    ApnsAuthError,
    ApnsConfigError,
    TokenProvider,
    build_jwt,
    load_private_key,
    make_token_provider,
    sign_es256,
)
from apns_es256.jwt import b64url

from _stubs import FAKE_KEY_ID, FAKE_TEAM_ID

cryptography = pytest.importorskip(
    "cryptography", reason="签名相关测试需要 cryptography（测试自身即时生成密钥）"
)

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: E402


def _decode_segment(segment: str) -> dict:
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))


@pytest.fixture(scope="module")
def ec_key() -> ec.EllipticCurvePrivateKey:
    """测试专用的临时 P-256 私钥（每次运行新生成，非任何真实密钥）。"""
    return ec.generate_private_key(ec.SECP256R1())


@pytest.fixture(scope="module")
def ec_key_pem(ec_key: ec.EllipticCurvePrivateKey) -> bytes:
    return ec_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


class TestBuildJwt:
    def test_structure_is_three_segments(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        token = build_jwt(key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key)
        parts = token.split(".")
        assert len(parts) == 3
        assert all(parts), "三段都不能为空"

    def test_header_contents(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        token = build_jwt(key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key)
        header = _decode_segment(token.split(".")[0])
        assert header == {"alg": "ES256", "kid": FAKE_KEY_ID}

    def test_claims_contents(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        token = build_jwt(
            key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key, issued_at=1700000000
        )
        claims = _decode_segment(token.split(".")[1])
        assert claims["iss"] == FAKE_TEAM_ID
        assert claims["iat"] == 1700000000
        # exp 是 JWT 常规字段；Apple 只校验 iss/iat，带上它是为了让下游能自行判过期
        assert claims["exp"] == 1700000000 + 3000

    def test_exp_defaults_to_ttl_after_iat(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        token = build_jwt(
            key_id=FAKE_KEY_ID,
            team_id=FAKE_TEAM_ID,
            private_key=ec_key,
            issued_at=1000,
            ttl=600,
        )
        claims = _decode_segment(token.split(".")[1])
        assert claims["exp"] - claims["iat"] == 600

    def test_exp_never_before_iat(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        """ttl 传 0 或负数时不能让 exp <= iat（否则 token 天生过期）。"""
        for bad_ttl in (0, -100):
            token = build_jwt(
                key_id=FAKE_KEY_ID,
                team_id=FAKE_TEAM_ID,
                private_key=ec_key,
                issued_at=1000,
                ttl=bad_ttl,
            )
            claims = _decode_segment(token.split(".")[1])
            assert claims["exp"] > claims["iat"], f"ttl={bad_ttl} 时 exp 仍须大于 iat"

    def test_header_has_no_exp(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        """exp 只能出现在 claims 里，不能混进 header。"""
        token = build_jwt(
            key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key, issued_at=1000
        )
        header = _decode_segment(token.split(".")[0])
        assert set(header) == {"alg", "kid"}

    def test_signature_is_64_bytes(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        """JWT 第三段解出来必须是 64 字节 —— 这就是 R‖S 的定长要求。"""
        token = build_jwt(key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key)
        signature = token.split(".")[2]
        raw = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        assert len(raw) == 64

    def test_base64url_has_no_padding_or_unsafe_chars(
        self, ec_key: ec.EllipticCurvePrivateKey
    ) -> None:
        token = build_jwt(key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key)
        assert "=" not in token
        assert "+" not in token and "/" not in token

    def test_missing_key_id_rejected(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        with pytest.raises(ApnsConfigError, match="key_id"):
            build_jwt(key_id="", team_id=FAKE_TEAM_ID, private_key=ec_key)

    def test_missing_team_id_rejected(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        with pytest.raises(ApnsConfigError, match="team_id"):
            build_jwt(key_id=FAKE_KEY_ID, team_id="   ", private_key=ec_key)

    def test_no_key_and_no_signer_rejected(self) -> None:
        with pytest.raises(ApnsConfigError, match="private_key 或 signer"):
            build_jwt(key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID)


class TestRealCryptography:
    """用真密钥验证 DER→R‖S 转换产生的签名确实能通过 ECDSA 验签。"""

    def test_signature_verifies_with_public_key(
        self, ec_key: ec.EllipticCurvePrivateKey
    ) -> None:
        token = build_jwt(key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key)
        header_b64, claims_b64, sig_b64 = token.split(".")
        signing_input = f"{header_b64}.{claims_b64}".encode("ascii")

        raw_sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        assert len(raw_sig) == 64

        r, s = utils.decode_dss_signature(
            # 把 R‖S 转回 DER，再用标准 API 验签 —— 等价于验证转换无损
            _raw_to_der_for_verify(raw_sig)
        )

        # 直接用公钥验签（cryptography 的 verify 收 DER，所以先转）
        ec_key.public_key().verify(
            _raw_to_der_for_verify(raw_sig),
            signing_input,
            ec.ECDSA(hashes.SHA256()),
        )
        assert r > 0 and s > 0

    def test_tampered_payload_fails_verification(
        self, ec_key: ec.EllipticCurvePrivateKey
    ) -> None:
        """改一个字节就必须验签失败 —— 证明这确实是被签过的内容。"""
        token = build_jwt(key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key)
        header_b64, claims_b64, sig_b64 = token.split(".")
        raw_sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))

        tampered = json.dumps({"iss": "SOMEONEELSE", "iat": 1700000000},
                              separators=(",", ":"), sort_keys=True).encode()
        bad_input = f"{header_b64}.{b64url(tampered)}".encode("ascii")

        with pytest.raises(Exception):
            ec_key.public_key().verify(
                _raw_to_der_for_verify(raw_sig), bad_input, ec.ECDSA(hashes.SHA256())
            )

    def test_der_vs_raw_differ(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        """确认我们真的做了转换：DER 长度不恒为 64，原始格式恒为 64。"""
        signing_input = b"probe"
        raw = sign_es256(signing_input, ec_key)
        der = ec_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))

        assert len(raw) == 64
        assert der[0] == 0x30
        # DER 长度会浮动（70~72 之间），若碰巧等于 64 则说明测试假设需复核
        assert len(der) != 64


def _raw_to_der_for_verify(raw: bytes) -> bytes:
    """测试辅助：R‖S → DER，用于调用 cryptography 的 verify。"""
    from apns_es256 import raw_to_der

    return raw_to_der(raw)


class TestLoadPrivateKey:
    def test_load_from_pem_bytes(self, ec_key_pem: bytes) -> None:
        key = load_private_key(key_pem=ec_key_pem)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_load_from_pem_str(self, ec_key_pem: bytes) -> None:
        key = load_private_key(key_pem=ec_key_pem.decode("utf-8"))
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_load_from_path(self, tmp_path, ec_key_pem: bytes) -> None:
        path = tmp_path / "AuthKey_PLACEHOLDER.p8"
        path.write_bytes(ec_key_pem)
        key = load_private_key(key_path=path)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

    def test_missing_both_rejected(self) -> None:
        with pytest.raises(ApnsConfigError, match="key_path 或 key_pem"):
            load_private_key()

    def test_nonexistent_path_rejected(self, tmp_path) -> None:
        with pytest.raises(ApnsConfigError, match="不存在"):
            load_private_key(key_path=tmp_path / "nope.p8")

    def test_garbage_pem_rejected(self) -> None:
        with pytest.raises(ApnsConfigError, match="解析失败"):
            load_private_key(key_pem=b"not a pem at all")

    def test_wrong_curve_rejected(self) -> None:
        """P-384 私钥必须被拒绝 —— APNs ES256 只接受 P-256。"""
        other = ec.generate_private_key(ec.SECP384R1())
        pem = other.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with pytest.raises(ApnsConfigError, match="P-256"):
            load_private_key(key_pem=pem)


class TestTokenProvider:
    def test_caches_within_ttl(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        clock = [1000.0]
        provider = TokenProvider(
            key_id=FAKE_KEY_ID,
            team_id=FAKE_TEAM_ID,
            private_key=ec_key,
            ttl=100,
            clock=lambda: clock[0],
        )
        first = provider.get()
        clock[0] += 50
        assert provider.get() == first, "TTL 内必须复用，不能重签"

    def test_reissues_after_ttl(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        clock = [1000.0]
        provider = TokenProvider(
            key_id=FAKE_KEY_ID,
            team_id=FAKE_TEAM_ID,
            private_key=ec_key,
            ttl=100,
            clock=lambda: clock[0],
        )
        first = provider.get()
        clock[0] += 101
        second = provider.get()
        assert second != first, "过期后必须重签"
        # iat 应反映新的时间
        assert _decode_segment(second.split(".")[1])["iat"] == 1101

    def test_invalidate_forces_reissue(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        clock = [1000.0]
        provider = TokenProvider(
            key_id=FAKE_KEY_ID,
            team_id=FAKE_TEAM_ID,
            private_key=ec_key,
            ttl=1000,
            clock=lambda: clock[0],
        )
        first = provider.get()
        provider.invalidate()
        clock[0] += 1
        assert provider.get() != first

    def test_is_callable(self, ec_key: ec.EllipticCurvePrivateKey) -> None:
        provider = TokenProvider(
            key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key
        )
        assert provider() == provider.get()

    def test_make_token_provider_from_pem(self, ec_key_pem: bytes) -> None:
        provider = make_token_provider(
            key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, key_pem=ec_key_pem
        )
        assert len(provider.get().split(".")) == 3

    def test_make_token_provider_with_signer_skips_cryptography(self) -> None:
        """注入 signer 时不应尝试加载私钥 —— 于是完全不需要 cryptography。"""
        provider = make_token_provider(
            key_id=FAKE_KEY_ID,
            team_id=FAKE_TEAM_ID,
            signer=lambda data, key: b"\x00" * 64,
        )
        token = provider.get()
        assert len(token.split(".")) == 3


class TestCustomSigner:
    def test_signer_receives_signing_input_and_key(self) -> None:
        seen: dict[str, object] = {}

        def signer(data: bytes, key: object) -> bytes:
            seen["data"] = data
            seen["key"] = key
            return b"\xab" * 64

        token = build_jwt(
            key_id=FAKE_KEY_ID,
            team_id=FAKE_TEAM_ID,
            private_key=object(),
            signer=signer,
            issued_at=1700000000,
        )
        header_b64, claims_b64, sig_b64 = token.split(".")
        assert seen["data"] == f"{header_b64}.{claims_b64}".encode("ascii")
        assert base64.urlsafe_b64decode(sig_b64 + "==") == b"\xab" * 64

    def test_wrong_signature_length_rejected(self) -> None:
        """signer 返回 DER（70~72 字节）而不是 64 字节时必须报错，而不是悄悄发出去。"""
        with pytest.raises(ApnsAuthError, match="64 字节"):
            build_jwt(
                key_id=FAKE_KEY_ID,
                team_id=FAKE_TEAM_ID,
                private_key=object(),
                signer=lambda data, key: b"\x30" * 71,
            )


class TestB64Url:
    def test_no_padding(self) -> None:
        assert "=" not in b64url(b"\x01\x02")

    def test_known_vector(self) -> None:
        # RFC 7515 附录 C 的经典例子
        assert b64url(b"\xfb\xff") == "-_8"
