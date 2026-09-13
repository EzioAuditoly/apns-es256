"""pytest 夹具。

关键约束：**所有测试必须完全离线**，不得向 Apple 发起任何真实请求。
本仓库的测试只使用 stub 传输层 / monkeypatch，从不构造真实网络连接。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# importlib 模式下 tests/ 不会自动进 sys.path，这里显式加一次。
_TESTS_DIR = Path(__file__).resolve().parent
if str(_TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(_TESTS_DIR))

from _stubs import StubTransport, make_config, make_test_key  # noqa: E402


@pytest.fixture
def stub_transport() -> StubTransport:
    """一个默认返回 200 的 stub 传输层。"""
    return StubTransport()


@pytest.fixture
def test_key(tmp_path):
    """运行时生成的一次性 EC P-256 私钥（非任何真实密钥）。"""
    return make_test_key(tmp_path)


@pytest.fixture
def config(tmp_path):
    """用假凭据 + 临时密钥文件构造的配置。"""
    _, key_path = make_test_key(tmp_path)
    return make_config(key_path)
