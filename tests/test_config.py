"""ApnsConfig 的测试：端点、环境变量、校验。"""

from __future__ import annotations

import pytest

from apns_es256 import ApnsConfig, ApnsConfigError, ApnsEnvironment
from apns_es256.config import (
    ENV_BUNDLE_ID,
    ENV_KEY_ID,
    ENV_KEY_PATH,
    ENV_TEAM_ID,
    PRODUCTION_HOST,
    SANDBOX_HOST,
)

from _stubs import FAKE_BUNDLE_ID, FAKE_KEY_ID, FAKE_TEAM_ID, make_test_key


def _valid(tmp_path, **overrides) -> ApnsConfig:
    _, key_path = make_test_key(tmp_path)
    values = {
        "key_id": FAKE_KEY_ID,
        "team_id": FAKE_TEAM_ID,
        "bundle_id": FAKE_BUNDLE_ID,
        "key_path": str(key_path),
    }
    values.update(overrides)
    return ApnsConfig(**values)


class TestEndpoints:
    """端点必须与源实现写死的两个 URL 完全一致。"""

    def test_production_host(self) -> None:
        assert PRODUCTION_HOST == "https://api.push.apple.com"

    def test_sandbox_host(self) -> None:
        assert SANDBOX_HOST == "https://api.sandbox.push.apple.com"

    def test_enum_base_urls(self) -> None:
        assert ApnsEnvironment.PRODUCTION.base_url == PRODUCTION_HOST
        assert ApnsEnvironment.SANDBOX.base_url == SANDBOX_HOST

    def test_default_environment_is_production(self, tmp_path) -> None:
        """源实现 use_sandbox 默认 False → 生产端点。"""
        assert _valid(tmp_path).environment is ApnsEnvironment.PRODUCTION

    def test_environment_accepts_string(self, tmp_path) -> None:
        assert _valid(tmp_path, environment="sandbox").environment is ApnsEnvironment.SANDBOX


class TestSourceDefaults:
    """抽取后必须保留源实现的数值默认值。"""

    def test_timeout_30(self, tmp_path) -> None:
        assert _valid(tmp_path).timeout == 30.0

    def test_no_retries_by_default(self, tmp_path) -> None:
        assert _valid(tmp_path).max_retries == 0

    def test_sandbox_fallback_on_by_default(self, tmp_path) -> None:
        assert _valid(tmp_path).sandbox_fallback is True


class TestValidation:
    def test_valid(self, tmp_path) -> None:
        assert _valid(tmp_path).topic == FAKE_BUNDLE_ID

    @pytest.mark.parametrize("field", ["key_id", "team_id", "bundle_id"])
    def test_missing_required_fields(self, tmp_path, field: str) -> None:
        with pytest.raises(ApnsConfigError, match=field):
            _valid(tmp_path, **{field: ""})

    def test_whitespace_only_rejected(self, tmp_path) -> None:
        with pytest.raises(ApnsConfigError, match="key_id"):
            _valid(tmp_path, key_id="   ")

    def test_missing_key_path(self, tmp_path) -> None:
        with pytest.raises(ApnsConfigError, match="私钥路径"):
            ApnsConfig(
                key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, bundle_id=FAKE_BUNDLE_ID
            )

    def test_nonexistent_key_path(self, tmp_path) -> None:
        with pytest.raises(ApnsConfigError, match="不存在"):
            _valid(tmp_path, key_path=str(tmp_path / "nope.p8"))

    def test_negative_timeout(self, tmp_path) -> None:
        with pytest.raises(ApnsConfigError, match="timeout"):
            _valid(tmp_path, timeout=0)

    def test_negative_max_retries(self, tmp_path) -> None:
        with pytest.raises(ApnsConfigError, match="max_retries"):
            _valid(tmp_path, max_retries=-1)

    def test_negative_backoff(self, tmp_path) -> None:
        with pytest.raises(ApnsConfigError, match="retry_backoff"):
            _valid(tmp_path, retry_backoff=-1)

    def test_invalid_environment(self, tmp_path) -> None:
        with pytest.raises(ApnsConfigError, match="environment"):
            _valid(tmp_path, environment="staging")

    def test_topic_stripped(self, tmp_path) -> None:
        assert _valid(tmp_path, bundle_id="  com.example.app  ").topic == "com.example.app"


class TestFromEnv:
    def test_reads_all(self, tmp_path) -> None:
        _, key_path = make_test_key(tmp_path)
        env = {
            ENV_KEY_ID: FAKE_KEY_ID,
            ENV_TEAM_ID: FAKE_TEAM_ID,
            ENV_BUNDLE_ID: FAKE_BUNDLE_ID,
            ENV_KEY_PATH: str(key_path),
        }
        config = ApnsConfig.from_env(env)
        assert config.key_id == FAKE_KEY_ID
        assert config.team_id == FAKE_TEAM_ID
        assert config.bundle_id == FAKE_BUNDLE_ID
        assert config.key_path == str(key_path)

    def test_overrides_win(self, tmp_path) -> None:
        _, key_path = make_test_key(tmp_path)
        env = {
            ENV_KEY_ID: "FROMENVENV",
            ENV_TEAM_ID: FAKE_TEAM_ID,
            ENV_BUNDLE_ID: FAKE_BUNDLE_ID,
            ENV_KEY_PATH: str(key_path),
        }
        assert ApnsConfig.from_env(env, key_id="EXPLICIT99").key_id == "EXPLICIT99"

    def test_empty_env_fails(self) -> None:
        with pytest.raises(ApnsConfigError):
            ApnsConfig.from_env({})

    def test_env_names_use_apns_prefix(self) -> None:
        for name in (ENV_KEY_ID, ENV_TEAM_ID, ENV_BUNDLE_ID, ENV_KEY_PATH):
            assert name.startswith("APNS_")
