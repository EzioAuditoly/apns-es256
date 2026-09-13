"""DER ``SEQUENCE{INTEGER r, INTEGER s}`` 与 JOSE 原始 ``R‖S`` 的互转。

抽取说明
--------
本模块把源实现中内联在 ``_generate_token()`` 里的两行签名格式转换逻辑
独立出来并补上完整校验::

    r, s = decode_dss_signature(der_sig)          # DER -> (int, int)
    raw_sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')   # -> R‖S

源实现依赖 ``cryptography`` 的 ``decode_dss_signature`` 来拆分 DER；这样写更省事，
但一来把 DER 解析交给了第三方（本库希望这一步零依赖），二来 ``to_bytes(32,'big')``
在分量超宽时会抛 ``OverflowError`` 而非给出可读错误。因此这里改为**纯标准库**的
DER 解析，并在超宽时抛出明确的 :class:`DerError`。转换结果与源实现逐字节一致。

背景
----
* **DER**（RFC 3279 / X9.62）：``SEQUENCE { INTEGER r, INTEGER s }``，每个 INTEGER
  用**最短**编码，所以长度可变（31/32/33 字节——33 字节是最高位为 1 时补 ``0x00``
  避免被当成负数）。OpenSSL、``cryptography``、Java、Go 吐出的都是这个格式。
* **JOSE 原始格式**（RFC 7518 §3.4，即 "R‖S"）：``r``、``s`` 各自定长大端拼接。
  P-256 每分量 32 字节，合计 **64 字节**。APNs 的 ES256 provider token 要的是这个。

把 DER 原样填进 JWT 签名，Apple 会回 ``403 InvalidProviderToken``，且报错完全不会
提示是编码问题——这是最常见的排查黑洞。
"""

from __future__ import annotations

# ASN.1 基础标签
_TAG_INTEGER = 0x02
_TAG_SEQUENCE = 0x30

#: 已知曲线 → 单个分量的定长字节数
CURVE_COMPONENT_SIZE = {
    "P-256": 32,
    "P-384": 48,
    "P-521": 66,
}


class DerError(ValueError):
    """DER 结构非法，或原始签名长度与曲线不匹配。"""


def signature_size(curve: str = "P-256") -> int:
    """返回该曲线 JOSE 原始签名的总字节数（P-256 → 64）。"""
    try:
        component = CURVE_COMPONENT_SIZE[curve]
    except KeyError:
        raise DerError(f"未知曲线: {curve!r}") from None
    return component * 2


def _read_length(data: bytes, offset: int) -> tuple[int, int]:
    """读取 DER 长度字段，返回 ``(length, 新偏移)``。"""
    if offset >= len(data):
        raise DerError("DER 截断：缺少长度字段")
    first = data[offset]
    offset += 1

    if first < 0x80:
        return first, offset

    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise DerError("DER 非法：不定长（indefinite length）不被接受")
    if num_bytes > 4:
        raise DerError(f"DER 非法：长度字段过长（{num_bytes} 字节）")
    if offset + num_bytes > len(data):
        raise DerError("DER 截断：长度字段不完整")

    length = int.from_bytes(data[offset : offset + num_bytes], "big")
    if length < 0x80:
        raise DerError("DER 非规范：应使用短形式长度")
    return length, offset + num_bytes


def _read_integer(data: bytes, offset: int) -> tuple[bytes, int]:
    """读取一个 DER INTEGER，返回 ``(值字节, 新偏移)``（已去符号前缀）。"""
    if offset >= len(data):
        raise DerError("DER 截断：缺少 INTEGER 标签")
    if data[offset] != _TAG_INTEGER:
        raise DerError(f"DER 非法：期望 INTEGER(0x02)，实际 0x{data[offset]:02x}")
    offset += 1

    length, offset = _read_length(data, offset)
    if length == 0:
        raise DerError("DER 非法：INTEGER 长度为 0")
    if offset + length > len(data):
        raise DerError("DER 截断：INTEGER 内容不完整")

    raw = data[offset : offset + length]
    offset += length

    # 去掉 INTEGER 的正数前缀零。DER 要求最高位为 1 时补一个 0x00。
    if raw[0] & 0x80:
        raise DerError("DER 非法：INTEGER 为负数，ECDSA 的 r/s 必须为正")
    while len(raw) > 1 and raw[0] == 0x00:
        raw = raw[1:]
    return raw, offset


def der_to_raw(signature: bytes, curve: str = "P-256") -> bytes:
    """DER ``SEQUENCE{INTEGER r, INTEGER s}`` → 定长 ``R‖S``。

    等价于源实现的 ``decode_dss_signature`` + 两次 ``to_bytes(32, 'big')``，
    但为纯标准库实现，且校验更严。

    :raises DerError: 结构非法或分量超出曲线位宽。
    """
    component = CURVE_COMPONENT_SIZE.get(curve)
    if component is None:
        raise DerError(f"未知曲线: {curve!r}")

    data = bytes(signature)
    if not data:
        raise DerError("签名为空")

    # 幂等保护：若已是定长原始格式，明确报错而不是猜。
    if len(data) == component * 2 and data[0] != _TAG_SEQUENCE:
        raise DerError(
            f"输入长度 {len(data)} 与 {curve} 原始格式一致且缺少 SEQUENCE 标签，"
            "看起来已经是 R‖S 格式，无需转换"
        )

    if data[0] != _TAG_SEQUENCE:
        raise DerError(f"DER 非法：期望 SEQUENCE(0x30)，实际 0x{data[0]:02x}")

    seq_len, offset = _read_length(data, 1)
    if offset + seq_len != len(data):
        raise DerError(
            f"DER 非法：SEQUENCE 声明长度 {seq_len} 与实际剩余 "
            f"{len(data) - offset} 不符"
        )

    r_bytes, offset = _read_integer(data, offset)
    s_bytes, offset = _read_integer(data, offset)

    if offset != len(data):
        raise DerError(f"DER 非法：SEQUENCE 内存在 {len(data) - offset} 字节多余数据")

    # 源实现走到这里会由 int.to_bytes(32,'big') 抛 OverflowError；这里给可读错误。
    if len(r_bytes) > component or len(s_bytes) > component:
        raise DerError(
            f"DER 非法：分量超出 {curve} 位宽"
            f"（r={len(r_bytes)}B, s={len(s_bytes)}B, 上限 {component}B）"
        )

    return r_bytes.rjust(component, b"\x00") + s_bytes.rjust(component, b"\x00")


def _encode_length(length: int) -> bytes:
    """把长度编码为 DER 长度字段（最短形式）。"""
    if length < 0:
        raise DerError("长度不能为负")
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def raw_to_der(raw: bytes, curve: str = "P-256") -> bytes:
    """定长 ``R‖S`` → DER ``SEQUENCE{INTEGER r, INTEGER s}``（逆向操作）。

    源实现没有这个方向；它是新增的，用于往返测试以及把 JOSE 签名交回原生
    OpenSSL API 的场景。
    """
    component = CURVE_COMPONENT_SIZE.get(curve)
    if component is None:
        raise DerError(f"未知曲线: {curve!r}")

    data = bytes(raw)
    expected = component * 2
    if len(data) != expected:
        raise DerError(f"原始签名长度应为 {expected} 字节（{curve}），实际 {len(data)}")

    def _encode_integer(value: bytes) -> bytes:
        stripped = value.lstrip(b"\x00") or b"\x00"
        # 最高位为 1 时必须补 0x00，否则会被解析成负数
        if stripped[0] & 0x80:
            stripped = b"\x00" + stripped
        return bytes([_TAG_INTEGER]) + _encode_length(len(stripped)) + stripped

    r = _encode_integer(data[:component])
    s = _encode_integer(data[component:])
    body = r + s
    return bytes([_TAG_SEQUENCE]) + _encode_length(len(body)) + body


def split_raw(raw: bytes, curve: str = "P-256") -> tuple[bytes, bytes]:
    """把 ``R‖S`` 拆成 ``(r, s)`` 两个定长分量。"""
    component = CURVE_COMPONENT_SIZE.get(curve)
    if component is None:
        raise DerError(f"未知曲线: {curve!r}")
    data = bytes(raw)
    if len(data) != component * 2:
        raise DerError(f"原始签名长度应为 {component * 2} 字节，实际 {len(data)}")
    return data[:component], data[component:]


def join_raw(r: bytes, s: bytes, curve: str = "P-256") -> bytes:
    """把两个分量补齐为定长并拼成 ``R‖S``。"""
    component = CURVE_COMPONENT_SIZE.get(curve)
    if component is None:
        raise DerError(f"未知曲线: {curve!r}")
    for name, value in (("r", r), ("s", s)):
        if len(value) > component:
            raise DerError(f"分量 {name} 超出 {curve} 位宽（{len(value)}B > {component}B）")
    return bytes(r).rjust(component, b"\x00") + bytes(s).rjust(component, b"\x00")
