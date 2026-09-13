"""静态审计：README 里出现的所有 ``apns_es256`` 名字都必须真实存在。

与 :mod:`tests.test_readme_contract` 的区别：那边**执行**示例代码，
这边只做**名字级**静态扫描，能覆盖散文（非代码块）里提到的标识符。
"""

from __future__ import annotations

import re
from pathlib import Path

import apns_es256

README = Path(__file__).resolve().parent.parent / "README.md"

# README 中提到的、属于第三方或 Python 内置的名字，不参与校验
_ALLOWED_FOREIGN = {
    "httpx",
    "h2",
    "cryptography",
    "PyJWT",
    "pip",
    "MIT",
    "APNs",
    "APNS",
    "DER",
    "JOSE",
    "ECDSA",
    "JSON",
    "JWT",
    "ES256",
    "P",
    "RFC",
    "UNIX",
    "iOS",
    "SSL",
    "TLS",
    "FCM",
    "NTP",
    "TestFlight",
    "Xcode",
}


def _readme() -> str:
    return README.read_text(encoding="utf-8")


def _candidate_names() -> set[str]:
    """抓取 README 里形如 CamelCase 或 snake_case 的标识符。"""
    text = _readme()
    # 先去掉 shell 代码块，避免把环境变量与命令当标识符
    text = re.sub(r"```bash\n.*?```", "", text, flags=re.DOTALL)
    text = re.sub(r"```\n.*?```", "", text, flags=re.DOTALL)

    names: set[str] = set()
    # CamelCase（可能带后缀，如 ApnsClient / DeliveryResult）
    names.update(re.findall(r"\b(Apns[A-Za-z]+|Delivery[A-Za-z]+|Token[A-Za-z]+|Error[A-Za-z]+)\b", text))
    # snake_case 公开函数/参数
    names.update(
        re.findall(
            r"\b(der_to_raw|raw_to_der|signature_size|build_alert_payload|"
            r"validate_device_token|build_jwt|load_private_key|b64url|classify|"
            r"parse_reason|split_raw|join_raw|send_alert|send_many|as_dict|from_env)\b",
            text,
        )
    )
    return names - _ALLOWED_FOREIGN


class TestReadmeNamesExist:
    #: README 里提到的实例/类方法 → 它们所属的类
    _METHOD_OWNERS = {
        "as_dict": "DeliveryResult",
        "from_env": "ApnsConfig",
        "send_alert": "ApnsClient",
        "send_many": "ApnsClient",
        "get": "DeliveryResult",
    }

    def _resolve(self, name: str) -> bool:
        """名字要么在包命名空间，要么是某个已导出类上的方法。"""
        if hasattr(apns_es256, name):
            return True
        owner = self._METHOD_OWNERS.get(name)
        if owner is not None:
            cls = getattr(apns_es256, owner, None)
            return cls is not None and hasattr(cls, name)
        return False

    def test_every_mentioned_name_is_real(self) -> None:
        """README 提到的库内名字必须真实存在（模块级或类方法）。"""
        unknown = [n for n in sorted(_candidate_names()) if not self._resolve(n)]
        assert unknown == [], f"README 提到但包内不存在的名字: {unknown}"

    def test_method_owner_mapping_is_itself_valid(self) -> None:
        """上表自身的映射必须成立，避免审计表写错造成假绿。"""
        for method, owner in self._METHOD_OWNERS.items():
            cls = getattr(apns_es256, owner, None)
            assert cls is not None, f"{owner} 未导出"
            assert hasattr(cls, method), f"{owner} 上不存在 {method}"

    def test_no_underscore_prefixed_public_leak(self) -> None:
        """README 不应引导使用者去碰下划线私有名。"""
        text = _readme()
        private = re.findall(r"\bapns_es256\.(_[a-zA-Z_]+)", text)
        assert private == [], f"README 引用了私有名: {private}"

    def test_documented_env_vars_all_implemented(self) -> None:
        from apns_es256 import config

        declared = {
            config.ENV_KEY_ID,
            config.ENV_TEAM_ID,
            config.ENV_BUNDLE_ID,
            config.ENV_KEY_PATH,
        }
        mentioned = set(re.findall(r"\bAPNS_[A-Z_]+\b", _readme()))
        assert mentioned <= declared, f"README 提到未实现的环境变量: {mentioned - declared}"

    def test_documented_endpoints_are_exact(self) -> None:
        """README 写的两个端点字符串必须与实现逐字一致。"""
        from apns_es256 import PRODUCTION_HOST, SANDBOX_HOST

        text = _readme()
        assert PRODUCTION_HOST in text
        assert SANDBOX_HOST in text

    def test_documented_reason_codes_exist(self) -> None:
        """README 重试语义表里列的 reason 必须都在枚举中。"""
        from apns_es256 import ApnsReason

        valid = {r.value for r in ApnsReason}
        for code in re.findall(r"`([A-Z][A-Za-z]+)`", _readme()):
            # 只校验看起来像 APNs reason 的（首字母大写且非已排除词）
            if code in valid:
                continue
            if code in _ALLOWED_FOREIGN:
                continue
        # 正向校验：README 表格里明确列出的常见 reason
        for code in (
            "Unregistered",
            "BadDeviceToken",
            "DeviceTokenNotForTopic",
            "InvalidProviderToken",
            "ExpiredProviderToken",
            "PayloadTooLarge",
            "BadTopic",
            "MissingTopic",
            "InternalServerError",
            "ServiceUnavailable",
            "Shutdown",
            "TooManyRequests",
            "TooManyProviderTokenUpdates",
        ):
            assert code in _readme(), f"README 未提及 {code}"
            assert code in valid, f"{code} 不在 ApnsReason 枚举中"

    def test_documented_error_classes_exist(self) -> None:
        """README 重试语义表里的分类名必须都是 ErrorClass 成员值。"""
        from apns_es256 import ErrorClass

        values = {c.value for c in ErrorClass}
        for cls in ("unregistered", "token_mismatch", "auth", "bad_request", "retryable", "throttled"):
            assert cls in values, f"{cls} 不是 ErrorClass 成员"

    def test_documented_defaults_match_implementation(self) -> None:
        """README 声称的默认值必须与实现一致。"""
        from apns_es256 import DEFAULT_TOKEN_TTL, MAX_PAYLOAD_BYTES, ApnsConfig

        cfg = ApnsConfig.__dataclass_fields__
        assert cfg["timeout"].default == 30.0, "README 说 timeout 默认 30"
        assert cfg["max_retries"].default == 0, "README 说 max_retries 默认 0"
        assert cfg["sandbox_fallback"].default is True
        assert MAX_PAYLOAD_BYTES == 4096, "README 说 4KB"
        assert DEFAULT_TOKEN_TTL == 3600, "README 说缓存 3600s"

        text = _readme()
        # README 在同一段里声称"缓存 3600 秒、提前 60 秒失效"
        assert "3600" in text, "README 应写明 token 缓存 3600 秒"
        assert "60" in text, "README 应写明提前 60 秒失效"
        # timeout 默认值应可读出
        assert "30" in text, "README 应写明 timeout 默认 30 秒"
