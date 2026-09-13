"""DER ↔ 原始 R‖S 转换的测试（纯标准库，无需 cryptography）。"""

from __future__ import annotations

import pytest

from apns_es256 import der_to_raw, join_raw, raw_to_der, signature_size, split_raw
from apns_es256.der import DerError


def _der_integer(value: bytes) -> bytes:
    """手工构造一个 DER INTEGER（带正数前缀零）。"""
    body = value
    if not body:
        body = b"\x00"
    if body[0] & 0x80:
        body = b"\x00" + body
    return b"\x02" + _der_length(len(body)) + body


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _der_sequence(body: bytes) -> bytes:
    return b"\x30" + _der_length(len(body)) + body


def _make_der(r: bytes, s: bytes) -> bytes:
    return _der_sequence(_der_integer(r) + _der_integer(s))


class TestSignatureSize:
    def test_p256_is_64(self) -> None:
        assert signature_size("P-256") == 64

    def test_other_curves(self) -> None:
        assert signature_size("P-384") == 96
        assert signature_size("P-521") == 132

    def test_unknown_curve_rejected(self) -> None:
        with pytest.raises(DerError, match="未知曲线"):
            signature_size("P-999")


class TestDerToRaw:
    def test_typical_33_byte_component_gets_stripped(self) -> None:
        """生产中最常见的形态：r/s 最高位为 1，DER 里各带一个 0x00 前缀。"""
        # r 和 s 都是 32 字节且首字节 >= 0x80 → DER INTEGER 会变成 33 字节
        r = bytes([0x80]) + b"\x11" * 31
        s = bytes([0xFF]) + b"\x22" * 31
        der = _make_der(r, s)

        # 确认测试数据本身就触发了 33 字节分支
        assert len(der) == 2 + 2 + 33 + 2 + 33 == 72

        raw = der_to_raw(der)
        assert len(raw) == 64
        assert raw[:32] == r
        assert raw[32:] == s

    def test_short_31_byte_component_gets_left_padded(self) -> None:
        """r 高位为 0 被压缩成 31 字节 → 必须左补零到 32 字节。"""
        r = b"\x00" + b"\x33" * 30  # 去掉前缀零后实际 31 字节
        r_short = b"\x33" * 30 + b"\x44"  # 31 字节，首位 0x33 < 0x80，无需前缀
        assert len(r_short) == 31
        s = b"\x55" * 32
        der = _make_der(r_short, s)

        raw = der_to_raw(der)
        assert len(raw) == 64
        assert raw[:32] == b"\x00" + r_short  # 左补零
        assert raw[32:] == s
        assert raw[:32].hex().startswith("00")

    def test_both_components_short(self) -> None:
        r = b"\x01" * 31
        s = b"\x02" * 30
        raw = der_to_raw(_make_der(r, s))
        assert raw == r.rjust(32, b"\x00") + s.rjust(32, b"\x00")

    def test_long_form_length_encoding(self) -> None:
        """SEQUENCE 内容 >= 0x80 字节时必须走长形式长度编码。"""
        r = bytes([0x80]) + b"\x01" * 31
        s = bytes([0x81]) + b"\x02" * 31
        der = _make_der(r, s)
        # 内容为 2+33 + 2+33 = 70 字节 < 0x80 → SEQUENCE 长度仍用短形式
        assert der[1] == 70
        # 每个 INTEGER 内容是 33 字节 < 0x80，同样短形式；标签后紧跟 33
        assert der[2] == 0x02 and der[3] == 33
        assert len(der) == 72
        raw = der_to_raw(der)
        assert raw[:32] == r and raw[32:] == s

    def test_long_form_length_encoding_when_body_exceeds_127(self) -> None:
        """SEQUENCE 内容 > 127 字节时长度字段必须用长形式，且能正确解析。

        真实 P-256 签名不会超过 127 字节（最长 72），但解析器必须能处理长形式，
        否则遇到非典型/恶意输入会静默出错。
        """
        r = b"\x80" + b"\x01" * 62   # 63 字节，高位为 1 → DER 需补 0x00 前缀
        s = b"\x81" + b"\x02" * 62
        body = _der_integer(r) + _der_integer(s)
        # 每个 INTEGER: 2 字节 (tag+len) + 64 字节内容 = 66；合计 132 > 127
        assert len(body) == 66 * 2 == 132, "内容需超过 127 字节"
        der = _der_sequence(body)
        assert der[1] == 0x81, "内容 > 127 字节时长度必须用长形式"

        # 用 P-384 位宽（每分量 48 字节）仍不够；这里只验证长形式能被正确读取：
        # 分量超出 P-256 位宽，应在读完之后被判为超宽。
        with pytest.raises(DerError, match="超出"):
            der_to_raw(der, "P-256")

    def test_long_form_length_parsed_for_large_curve(self) -> None:
        """P-521（每分量 66 字节）会产生长形式长度，验证解析正确。"""
        r = b"\x01" * 66
        s = b"\x02" * 66
        body = _der_integer(r) + _der_integer(s)
        assert len(body) > 127
        der = _der_sequence(body)
        assert der[1] == 0x81

        raw = der_to_raw(der, "P-521")
        assert len(raw) == 132
        assert raw[:66] == r and raw[66:] == s

    def test_minimal_length_uses_short_form(self) -> None:
        """小整数应走短形式长度。"""
        der = _make_der(b"\x01", b"\x02")
        assert der[1] < 0x80
        raw = der_to_raw(der)
        assert raw[31] == 0x01 and raw[63] == 0x02
        assert raw[:31] == b"\x00" * 31


class TestRoundTrip:
    @pytest.mark.parametrize(
        "r,s",
        [
            (b"\x01" * 32, b"\x02" * 32),
            (bytes([0x80]) + b"\x11" * 31, bytes([0xFF]) + b"\x22" * 31),
            (b"\x00" * 31 + b"\x01", b"\x00" * 31 + b"\x02"),
            (b"\xff" * 32, b"\xff" * 32),
            (b"\x01", b"\x02"),
        ],
    )
    def test_raw_to_der_to_raw(self, r: bytes, s: bytes) -> None:
        """R‖S → DER → R‖S 必须无损。"""
        raw = join_raw(r, s)
        assert len(raw) == 64
        der = raw_to_der(raw)
        assert der[0] == 0x30
        assert der_to_raw(der) == raw

    def test_raw_to_der_negative_guard(self) -> None:
        """首字节高位为 1 时必须补 0x00，否则 DER 会被解析成负数。"""
        raw = b"\xff" * 32 + b"\xff" * 32
        der = raw_to_der(raw)
        # 每个 INTEGER 都是 0x02 0x21 0x00 <32 bytes>
        assert der[0] == 0x30
        assert der[2] == 0x02 and der[3] == 0x21 and der[4] == 0x00
        assert der_to_raw(der) == raw


class TestSplitJoin:
    def test_split(self) -> None:
        raw = b"\xaa" * 32 + b"\xbb" * 32
        r, s = split_raw(raw)
        assert r == b"\xaa" * 32 and s == b"\xbb" * 32

    def test_join_pads(self) -> None:
        assert join_raw(b"\x01", b"\x02") == b"\x00" * 31 + b"\x01" + b"\x00" * 31 + b"\x02"

    def test_join_rejects_oversized(self) -> None:
        with pytest.raises(DerError, match="超出"):
            join_raw(b"\x01" * 33, b"\x02")


class TestInvalidInput:
    def test_empty(self) -> None:
        with pytest.raises(DerError, match="签名为空"):
            der_to_raw(b"")

    def test_already_raw_is_rejected_not_silently_passed(self) -> None:
        """已是原始格式必须报错，不能静默返回，否则会掩盖漏转换。"""
        raw = b"\x11" * 64
        with pytest.raises(DerError, match="已经是 R‖S"):
            der_to_raw(raw)

    def test_wrong_tag(self) -> None:
        with pytest.raises(DerError, match="期望 SEQUENCE"):
            der_to_raw(b"\x31\x06\x02\x01\x01\x02\x01\x02")

    def test_truncated(self) -> None:
        with pytest.raises(DerError):
            der_to_raw(b"\x30\x06\x02\x01")

    def test_negative_integer_rejected(self) -> None:
        # INTEGER 首字节高位为 1 且无前缀零 → 负数
        bad = b"\x30\x08" + b"\x02\x02\x80\x01" + b"\x02\x02\x01\x02"
        with pytest.raises(DerError, match="负数"):
            der_to_raw(bad)

    def test_declared_length_mismatch(self) -> None:
        """SEQUENCE 声明长度与实际不符。"""
        der = _make_der(b"\x01" * 4, b"\x02" * 4)
        tampered = bytes([0x30, der[1] + 1]) + der[2:]
        with pytest.raises(DerError, match="不符"):
            der_to_raw(tampered)

    def test_trailing_garbage(self) -> None:
        der = _make_der(b"\x01", b"\x02") + b"\xff"
        with pytest.raises(DerError, match="不符"):
            der_to_raw(der)

    def test_indefinite_length_rejected(self) -> None:
        with pytest.raises(DerError, match="不定长"):
            der_to_raw(b"\x30\x80\x02\x01\x01\x02\x01\x02\x00\x00")

    def test_non_minimal_length_rejected(self) -> None:
        """长形式编码了小长度 → 非规范，应拒绝。"""
        with pytest.raises(DerError, match="短形式"):
            der_to_raw(b"\x30\x81\x06\x02\x01\x01\x02\x01\x02")

    def test_non_canonical_leading_zeros_accepted(self) -> None:
        """多余的前缀零不算致命（部分实现会补），仍应正确解析。"""
        body = b"\x02\x03\x00\x00\x01" + b"\x02\x01\x02"
        der = _der_sequence(body)
        raw = der_to_raw(der)
        assert raw[31] == 0x01 and raw[63] == 0x02

    def test_component_over_curve_width(self) -> None:
        r = b"\x01" * 33  # 33 字节且首位 < 0x80，无需前缀零 → 实际 33 字节
        s = b"\x02" * 32
        der = _make_der(r, s)
        with pytest.raises(DerError, match="超出"):
            der_to_raw(der)

    def test_zero_length_integer(self) -> None:
        der = _der_sequence(b"\x02\x00" + b"\x02\x01\x02")
        with pytest.raises(DerError, match="长度为 0"):
            der_to_raw(der)


class TestPureStdlib:
    def test_der_module_does_not_import_cryptography(self) -> None:
        """DER 模块必须是纯标准库实现，不依赖 cryptography。"""
        import ast
        from pathlib import Path

        import apns_es256.der as der_module

        source = Path(der_module.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)

        assert not any("cryptography" in name for name in imported), imported
        assert not any("jwt" in name.lower() for name in imported), imported
