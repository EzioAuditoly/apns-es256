"""ES256 provider token 的测试。

用**测试内部即时生成**的 EC P-256 密钥 —— 不涉及任何真实凭据。
最重要的一组是 :class:`TestExtractionFidelity`：逐字节比对抽取实现与源实现
（``decode_dss_signature`` + ``to_bytes(32,'big')``）的签名结果，
证明这次格式转换的抽取是无损的。
"""

from __future__ import annotations

import base64
import json

import pytest

from apns_es256 import (
    ApnsAuthError,
    ApnsConfigError,
    DEFAULT_TOKEN_SAFETY_MARGIN,
    DEFAULT_TOKEN_TTL,
    TokenProvider,
    b64url,
    build_jwt,
    load_private_key,
)
from apns_es256.der import der_to_raw

from _stubs import FAKE_KEY_ID, FAKE_TEAM_ID, make_test_key

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


class TestBuildJwt:
    def test_structure_is_three_segments(self, ec_key) -> None:
        token = build_jwt(key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key)
        parts = token.split(".")
        assert len(parts) == 3
        assert all(parts)

    def test_header_contents(self, ec_key) -> None:
        """源实现：header = {'alg': 'ES256', 'kid': self.key_id}"""
        token = build_jwt(key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key)
        assert _decode_segment(token.split(".")[0]) == {"alg": "ES256", "kid": FAKE_KEY_ID}

    def test_claims_contents(self, ec_key) -> None:
        """源实现：payload = {'iss': team_id, 'iat': now, 'exp': now + 3600}"""
        token = build_jwt(
            key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key, issued_at=1700000000
        )
        claims = _decode_segment(token.split(".")[1])
        assert claims["iss"] == FAKE_TEAM_ID
        assert claims["iat"] == 1700000000
        assert claims["exp"] == 1700000000 + DEFAULT_TOKEN_TTL

    def test_default_ttl_matches_source(self) -> None:
        """源实现写死 3600 秒 —— 抽取后默认值必须一致。"""
        assert DEFAULT_TOKEN_TTL == 3600

    def test_signature_is_64_bytes(self, ec_key) -> None:
        """JWT 第三段解出来必须是 64 字节 —— R‖S 的定长要求。"""
        token = build_jwt(key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key)
        sig = token.split(".")[2]
        assert len(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))) == 64

    def test_base64url_no_padding_or_unsafe_chars(self, ec_key) -> None:
        token = build_jwt(key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key)
        assert "=" not in token
        assert "+" not in token and "/" not in token

    def test_missing_key_id_rejected(self, ec_key) -> None:
        with pytest.raises(ApnsConfigError, match="key_id"):
            build_jwt(key_id="", team_id=FAKE_TEAM_ID, private_key=ec_key)

    def test_missing_team_id_rejected(self, ec_key) -> None:
        with pytest.raises(ApnsConfigError, match="team_id"):
            build_jwt(key_id=FAKE_KEY_ID, team_id="   ", private_key=ec_key)

    def test_no_key_source_rejected(self) -> None:
        with pytest.raises(ApnsConfigError, match="key_path 或 private_key"):
            build_jwt(key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID)


class TestExtractionFidelity:
    """逐字节证明：抽取的 DER→R‖S 实现与源实现行为完全一致。

    源实现（push_service.py L83-84）::

        r, s = decode_dss_signature(der_sig)
        raw_sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    """

    def test_matches_source_implementation_exactly(self, ec_key) -> None:
        signing_input = b"header.claims"
        der_sig = ec_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))

        # —— 源实现的做法（照抄）——
        r, s = utils.decode_dss_signature(der_sig)
        source_raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")

        # —— 抽取实现 ——
        extracted_raw = der_to_raw(der_sig, "P-256")

        assert extracted_raw == source_raw, "抽取实现必须与源实现逐字节一致"
        assert len(extracted_raw) == 64

    @pytest.mark.parametrize("_attempt", range(8))
    def test_matches_source_across_many_signatures(self, ec_key, _attempt: int) -> None:
        """跑多次以覆盖 r/s 长度不同的各种情形（31/32/33 字节分支）。"""
        payload = f"payload-{_attempt}".encode()
        der_sig = ec_key.sign(payload, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der_sig)
        assert der_to_raw(der_sig, "P-256") == r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def test_jwt_signature_verifies_with_public_key(self, ec_key) -> None:
        """用公钥独立验签，证明整条链路（DER→R‖S→base64url）正确。"""
        from apns_es256 import raw_to_der

        token = build_jwt(key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key)
        header_b64, claims_b64, sig_b64 = token.split(".")
        raw_sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))

        ec_key.public_key().verify(
            raw_to_der(raw_sig),
            f"{header_b64}.{claims_b64}".encode("ascii"),
            ec.ECDSA(hashes.SHA256()),
        )

    def test_tampered_claims_fail_verification(self, ec_key) -> None:
        from apns_es256 import raw_to_der

        token = build_jwt(key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key)
        header_b64, _, sig_b64 = token.split(".")
        raw_sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))

        tampered = json.dumps(
            {"iss": "SOMEONEELSE", "iat": 1, "exp": 2}, separators=(",", ":"), sort_keys=True
        ).encode()
        with pytest.raises(Exception):
            ec_key.public_key().verify(
                raw_to_der(raw_sig),
                f"{header_b64}.{b64url(tampered)}".encode("ascii"),
                ec.ECDSA(hashes.SHA256()),
            )


class TestLoadPrivateKey:
    def test_loads_generated_key(self, test_key) -> None:
        _, path = test_key
        assert isinstance(load_private_key(path), ec.EllipticCurvePrivateKey)

    def test_accepts_str_path(self, test_key) -> None:
        _, path = test_key
        assert isinstance(load_private_key(str(path)), ec.EllipticCurvePrivateKey)

    def test_nonexistent_path_rejected(self, tmp_path) -> None:
        with pytest.raises(ApnsConfigError, match="不存在"):
            load_private_key(tmp_path / "nope.p8")

    def test_garbage_pem_rejected(self, tmp_path) -> None:
        bad = tmp_path / "bad.p8"
        bad.write_bytes(b"not a pem")
        with pytest.raises(ApnsConfigError, match="解析失败"):
            load_private_key(bad)

    def test_error_does_not_echo_file_content(self, tmp_path) -> None:
        """异常文本不得回显密钥内容/路径细节（脱敏要求）。"""
        bad = tmp_path / "secret.p8"
        bad.write_bytes(b"-----BEGIN PRIVATE KEY-----\nSUPERSECRET\n-----END PRIVATE KEY-----\n")
        with pytest.raises(ApnsConfigError) as excinfo:
            load_private_key(bad)
        assert "SUPERSECRET" not in str(excinfo.value)

    def test_wrong_curve_rejected(self, tmp_path) -> None:
        """P-384 必须被拒绝 —— APNs ES256 只接受 P-256。源实现无此校验。"""
        other = ec.generate_private_key(ec.SECP384R1())
        pem = other.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path = tmp_path / "p384.p8"
        path.write_bytes(pem)
        with pytest.raises(ApnsConfigError, match="P-256"):
            load_private_key(path)


class TestTokenProvider:
    """缓存语义必须与源实现一致：3600s 有效期、提前 60s 失效。"""

    def test_source_defaults(self) -> None:
        assert DEFAULT_TOKEN_TTL == 3600
        assert DEFAULT_TOKEN_SAFETY_MARGIN == 60

    def _provider(self, ec_key, clock, **kwargs) -> TokenProvider:
        return TokenProvider(
            key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=ec_key, clock=clock, **kwargs
        )

    def test_caches_within_validity(self, ec_key) -> None:
        clock = [1000.0]
        provider = self._provider(ec_key, lambda: clock[0])
        first = provider.get()
        clock[0] += 3000  # 距过期还有 600s，超过 60s 余量
        assert provider.get() == first

    def test_reissues_inside_safety_margin(self, ec_key) -> None:
        """源实现条件 time.time() < expire - 60 —— 进入最后 60s 必须重签。"""
        clock = [1000.0]
        provider = self._provider(ec_key, lambda: clock[0])
        first = provider.get()
        clock[0] += 3600 - 30  # 只剩 30s，落在 60s 余量内
        assert provider.get() != first

    def test_reissues_after_expiry(self, ec_key) -> None:
        clock = [1000.0]
        provider = self._provider(ec_key, lambda: clock[0])
        first = provider.get()
        clock[0] += 3601
        assert provider.get() != first

    def test_new_iat_reflects_clock(self, ec_key) -> None:
        clock = [1000.0]
        provider = self._provider(ec_key, lambda: clock[0])
        provider.get()
        clock[0] += 4000
        claims = _decode_segment(provider.get().split(".")[1])  # type: ignore[union-attr]
        assert claims["iat"] == 5000

    def test_invalidate_forces_reissue(self, ec_key) -> None:
        clock = [1000.0]
        provider = self._provider(ec_key, lambda: clock[0])
        first = provider.get()
        provider.invalidate()
        clock[0] += 1
        assert provider.get() != first

    def test_callable(self, ec_key) -> None:
        clock = [1000.0]
        provider = self._provider(ec_key, lambda: clock[0])
        assert provider() == provider.get()

    def test_get_returns_none_on_broken_key(self) -> None:
        """源实现在签名失败时 return None —— get() 保留该语义。"""
        provider = TokenProvider(
            key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=object()
        )
        assert provider.get() is None

    def test_get_or_raise_raises_on_broken_key(self) -> None:
        provider = TokenProvider(
            key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, private_key=object()
        )
        with pytest.raises(ApnsAuthError):
            provider.get_or_raise()

    def test_loads_key_once_from_path(self, test_key) -> None:
        """源实现每次重签都重新读盘；抽取后只加载一次（性能改进）。"""
        _, path = test_key
        clock = [1000.0]
        provider = TokenProvider(
            key_id=FAKE_KEY_ID,
            team_id=FAKE_TEAM_ID,
            key_path=path,
            clock=lambda: clock[0],
        )
        provider.get()
        path.unlink()  # 删掉文件
        clock[0] += 4000
        assert provider.get() is not None, "密钥已缓存，删文件后仍应能重签"


class TestB64Url:
    def test_no_padding(self) -> None:
        assert "=" not in b64url(b"\x01\x02")

    def test_known_vector(self) -> None:
        # RFC 7515 附录 C
        assert b64url(b"\xfb\xff") == "-_8"
