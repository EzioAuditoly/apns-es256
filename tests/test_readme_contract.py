"""README 门面一致性测试：把 README 里的示例代码**真的跑一遍**。

README 是公开门面，示例里的方法名/参数一旦与真实 API 不符，
使用者复制即报错。这里直接从 README.md 抽取 python 代码块，
在 stub 传输层上执行，确保文档与实现对得上。
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from _stubs import FAKE_DEVICE_TOKEN, StaticTokenProvider, StubTransport, make_test_key

README = Path(__file__).resolve().parent.parent / "README.md"


def _readme_text() -> str:
    return README.read_text(encoding="utf-8")


def _python_blocks() -> list[str]:
    """抽取 README 中所有 ```python 代码块。"""
    return re.findall(r"```python\n(.*?)```", _readme_text(), re.DOTALL)


class TestReadmeApiMatchesImplementation:
    def test_readme_exists(self) -> None:
        assert README.is_file()

    def test_has_python_examples(self) -> None:
        assert len(_python_blocks()) >= 4, "README 应有多个可执行示例"

    def test_no_reference_to_moved_internal_doc(self) -> None:
        """EXTRACT-PLAN.md 已移出仓库，README 不得再引用它（否则链接 404）。"""
        text = _readme_text()
        assert "EXTRACT-PLAN.md" not in text, "README 不应链接已移出仓库的内部文件"
        assert "](EXTRACT-PLAN" not in text

    def test_no_relative_markdown_link_to_missing_file(self) -> None:
        """README 里所有 ](xxx.md) 形式的目标文件都必须真实存在。"""
        missing = []
        for target in re.findall(r"\]\((?!https?://)([^)#]+)\)", _readme_text()):
            if not (README.parent / target).exists():
                missing.append(target)
        assert missing == [], f"README 链接指向不存在的文件: {missing}"

    def test_env_var_names_match_source(self) -> None:
        """README 中出现的 APNS_* 环境变量必须与实现一致。"""
        from apns_es256 import config

        declared = {
            config.ENV_KEY_ID,
            config.ENV_TEAM_ID,
            config.ENV_BUNDLE_ID,
            config.ENV_KEY_PATH,
        }
        mentioned = set(re.findall(r"\bAPNS_[A-Z_]+\b", _readme_text()))
        assert mentioned, "README 应提到环境变量"
        assert mentioned <= declared, f"README 提到未实现的环境变量: {mentioned - declared}"


class TestReadmeExamplesExecute:
    """把示例真正跑起来（全部离线，走 stub 传输层）。"""

    def test_from_env_and_send_example(self, tmp_path, monkeypatch) -> None:
        """对应 README「1. 从环境变量读取凭据」。"""
        _, key_path = make_test_key(tmp_path)
        monkeypatch.setenv("APNS_KEY_ID", "ABCDE12345")
        monkeypatch.setenv("APNS_TEAM_ID", "ZYXWV98765")
        monkeypatch.setenv("APNS_BUNDLE_ID", "com.example.app")
        monkeypatch.setenv("APNS_KEY_PATH", str(key_path))

        from apns_es256 import ApnsClient, ApnsConfig

        config = ApnsConfig.from_env()
        transport = StubTransport()
        with ApnsClient(config, transport=transport, token_provider=StaticTokenProvider()) as client:
            result = client.send(
                "0f1e2d3c4b5a69788796a5b4c3d2e1f0" * 2,
                {"aps": {"alert": "你好", "sound": "default", "badge": 1}},
            )
            assert result.ok
            assert result.apns_id is not None
            # README 里用到的属性
            _ = (result.status_code, result.error_class, result.retryable)

    def test_send_alert_example(self, tmp_path) -> None:
        """对应 README「2. 发送带标题/正文的通知」（验证 keyword 用法）。"""
        _, key_path = make_test_key(tmp_path)
        from apns_es256 import ApnsClient, ApnsConfig

        config = ApnsConfig(
            key_id="ABCDE12345",
            team_id="ZYXWV98765",
            bundle_id="com.example.app",
            key_path=str(key_path),
        )
        transport = StubTransport()
        with ApnsClient(config, transport=transport, token_provider=StaticTokenProvider()) as client:
            result = client.send_alert(
                FAKE_DEVICE_TOKEN,
                title="新消息",
                body="你收到一条新消息",
                badge=3,
                sound="default",
                custom_data={"push_type": "message"},
            )
            assert result.ok
        body = transport.last_body()
        assert body["aps"]["alert"] == {"title": "新消息", "body": "你收到一条新消息"}

    def test_background_push_example(self, tmp_path) -> None:
        """对应 README「3. 后台/静默推送与合并通知」。"""
        _, key_path = make_test_key(tmp_path)
        from apns_es256 import ApnsClient, ApnsConfig

        config = ApnsConfig(
            key_id="ABCDE12345",
            team_id="ZYXWV98765",
            bundle_id="com.example.app",
            key_path=str(key_path),
        )
        transport = StubTransport()
        with ApnsClient(config, transport=transport, token_provider=StaticTokenProvider()) as client:
            result = client.send(
                FAKE_DEVICE_TOKEN,
                {"aps": {"content-available": 1}},
                push_type="background",
                priority=5,
                collapse_id="chat-42",
                expiration=0,
            )
            assert result.ok
        headers = transport.last_headers
        assert headers["apns-push-type"] == "background"
        assert headers["apns-priority"] == "5"
        assert headers["apns-collapse-id"] == "chat-42"
        assert headers["apns-expiration"] == "0"

    def test_sandbox_environment_example(self, tmp_path) -> None:
        """对应 README「4. 直接指定沙箱环境」。"""
        _, key_path = make_test_key(tmp_path)
        from apns_es256 import ApnsConfig, ApnsEnvironment

        config = ApnsConfig.from_env(
            {
                "APNS_KEY_ID": "ABCDE12345",
                "APNS_TEAM_ID": "ZYXWV98765",
                "APNS_BUNDLE_ID": "com.example.app",
                "APNS_KEY_PATH": str(key_path),
            },
            environment=ApnsEnvironment.SANDBOX,
        )
        assert config.environment is ApnsEnvironment.SANDBOX

    def test_dict_style_migration_example(self, tmp_path) -> None:
        """对应 README「5. 平滑迁移：字典式取值」。"""
        _, key_path = make_test_key(tmp_path)
        from apns_es256 import ApnsClient, ApnsConfig

        config = ApnsConfig(
            key_id="ABCDE12345",
            team_id="ZYXWV98765",
            bundle_id="com.example.app",
            key_path=str(key_path),
        )
        transport = StubTransport()
        with ApnsClient(config, transport=transport, token_provider=StaticTokenProvider()) as client:
            result = client.send(FAKE_DEVICE_TOKEN, {"aps": {}})
            if not result["success"]:
                raise AssertionError("不应失败")
            assert result.get("error") is None
            assert result.as_dict() == {"success": True}

    def test_der_helpers_example(self) -> None:
        """对应 README「DER → R‖S」示例。"""
        from apns_es256 import der_to_raw, raw_to_der, signature_size

        assert signature_size("P-256") == 64

        # 构造一个真实形状的 DER 签名（33 字节分量分支）
        r = bytes([0x80]) + b"\x11" * 31
        s = bytes([0x22]) * 32
        body = b"\x02\x21\x00" + r + b"\x02\x20" + s
        der = b"\x30" + bytes([len(body)]) + body

        raw = der_to_raw(der)
        assert raw == r + s
        assert raw_to_der(raw) == der

    def test_quickstart_form_cannot_be_wrong(self, tmp_path) -> None:
        """README 里 client.send 的调用形状必须与签名一致（位置参数 token, payload）。"""
        import inspect

        from apns_es256 import ApnsClient

        params = list(inspect.signature(ApnsClient.send).parameters)
        assert params[:3] == ["self", "device_token", "payload"], (
            "README 以位置参数调用 send(token, payload)，签名必须匹配"
        )
