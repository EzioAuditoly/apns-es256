"""ApnsConfig 的测试：环境变量读取、校验、环境端点。"""

from __future__ import annotations

import pytest

from apns_es256 import ApnsConfig, ApnsConfigError, ApnsEnvironment
from apns_es256.config import (
    ENV_BUNDLE_ID,
    ENV_KEY_ID,
    ENV_KEY_PATH,
    ENV_KEY_PEM,
    ENV_TEAM_ID,
    PRODUCTION_HOST,
    SANDBOX_HOST,
)

from _stubs import FAKE_BUNDLE_ID, FAKE_KEY_ID, FAKE_TEAM_ID

PLACEHOLDER_PEM = "-----BEGIN PRIVATE KEY-----\nPLACEHOLDER\n-----END PRIVATE KEY-----\n"


def _valid(**overrides) -> ApnsConfig:
    values = {
        "key_id": FAKE_KEY_ID,
        "team_id": FAKE_TEAM_ID,
        "bundle_id": FAKE_BUNDLE_ID,
        "key_pem": PLACEHOLDER_PEM,
    }
    values.update(overrides)
    return ApnsConfig(**values)


class TestEndpoints:
    def test_production_host(self) -> None:
        assert PRODUCTION_HOST == "https://api.push.apple.com"

    def test_sandbox_host(self) -> None:
        assert SANDBOX_HOST == "https://api.sandbox.push.apple.com"

    def test_enum_base_urls(self) -> None:
        assert ApnsEnvironment.PRODUCTION.base_url == PRODUCTION_HOST
        assert ApnsEnvironment.SANDBOX.base_url == SANDBOX_HOST

    def test_other_environment(self) -> None:
        assert (
            _valid(environment=ApnsEnvironment.PRODUCTION).other_environment
            is ApnsEnvironment.SANDBOX
        )
        assert (
            _valid(environment=ApnsEnvironment.SANDBOX).other_environment
            is ApnsEnvironment.PRODUCTION
        )

    def test_default_environment_is_production(self) -> None:
        assert _valid().environment is ApnsEnvironment.PRODUCTION


class TestValidation:
    def test_valid_config(self) -> None:
        config = _valid()
        assert config.topic == FAKE_BUNDLE_ID

    @pytest.mark.parametrize("field", ["key_id", "team_id", "bundle_id"])
    def test_missing_required_fields(self, field: str) -> None:
        with pytest.raises(ApnsConfigError, match=field):
            _valid(**{field: ""})

    def test_whitespace_only_field_rejected(self) -> None:
        with pytest.raises(ApnsConfigError, match="key_id"):
            _valid(key_id="   ")

    def test_missing_key_material(self) -> None:
        with pytest.raises(ApnsConfigError, match="缺少私钥"):
            ApnsConfig(
                key_id=FAKE_KEY_ID, team_id=FAKE_TEAM_ID, bundle_id=FAKE_BUNDLE_ID
            )

    def test_both_key_path_and_pem_rejected(self, tmp_path) -> None:
        path = tmp_path / "x.p8"
        path.write_text(PLACEHOLDER_PEM)
        with pytest.raises(ApnsConfigError, match="只能提供其一"):
            _valid(key_path=str(path))

    def test_nonexistent_key_path_rejected(self, tmp_path) -> None:
        with pytest.raises(ApnsConfigError, match="不存在"):
            _valid(key_pem=None, key_path=str(tmp_path / "nope.p8"))

    def test_negative_timeout_rejected(self) -> None:
        with pytest.raises(ApnsConfigError, match="timeout"):
            _valid(timeout=0)

    def test_negative_max_retries_rejected(self) -> None:
        with pytest.raises(ApnsConfigError, match="max_retries"):
            _valid(max_retries=-1)

    def test_negative_backoff_rejected(self) -> None:
        with pytest.raises(ApnsConfigError, match="retry_backoff"):
            _valid(retry_backoff=-0.5)

    def test_zero_token_ttl_rejected(self) -> None:
        with pytest.raises(ApnsConfigError, match="token_ttl"):
            _valid(token_ttl=0)

    def test_invalid_environment_string_rejected(self) -> None:
        with pytest.raises(ApnsConfigError, match="environment"):
            _valid(environment="staging")

    def test_environment_accepts_string(self) -> None:
        config = _valid(environment="sandbox")
        assert config.environment is ApnsEnvironment.SANDBOX

    def test_topic_is_stripped(self) -> None:
        assert _valid(bundle_id="  com.example.app  ").topic == "com.example.app"


class TestFromEnv:
    def test_reads_all_env_vars(self) -> None:
        env = {
            ENV_KEY_ID: FAKE_KEY_ID,
            ENV_TEAM_ID: FAKE_TEAM_ID,
            ENV_BUNDLE_ID: FAKE_BUNDLE_ID,
            ENV_KEY_PEM: PLACEHOLDER_PEM,
        }
        config = ApnsConfig.from_env(env)
        assert config.key_id == FAKE_KEY_ID
        assert config.team_id == FAKE_TEAM_ID
        assert config.bundle_id == FAKE_BUNDLE_ID

    def test_reads_key_path(self, tmp_path) -> None:
        path = tmp_path / "AuthKey_PLACEHOLDER.p8"
        path.write_text(PLACEHOLDER_PEM)
        env = {
            ENV_KEY_ID: FAKE_KEY_ID,
            ENV_TEAM_ID: FAKE_TEAM_ID,
            ENV_BUNDLE_ID: FAKE_BUNDLE_ID,
            ENV_KEY_PATH: str(path),
        }
        config = ApnsConfig.from_env(env)
        assert config.key_path == str(path)
        assert config.key_pem is None

    def test_overrides_win_over_env(self) -> None:
        env = {
            ENV_KEY_ID: "FROMENVENV",
            ENV_TEAM_ID: FAKE_TEAM_ID,
            ENV_BUNDLE_ID: FAKE_BUNDLE_ID,
            ENV_KEY_PEM: PLACEHOLDER_PEM,
        }
        config = ApnsConfig.from_env(env, key_id="EXPLICIT99")
        assert config.key_id == "EXPLICIT99"

    def test_empty_env_missing_fields(self) -> None:
        with pytest.raises(ApnsConfigError):
            ApnsConfig.from_env({})

    def test_missing_pem_and_path(self) -> None:
        env = {
            ENV_KEY_ID: FAKE_KEY_ID,
            ENV_TEAM_ID: FAKE_TEAM_ID,
            ENV_BUNDLE_ID: FAKE_BUNDLE_ID,
        }
        with pytest.raises(ApnsConfigError, match="缺少私钥"):
            ApnsConfig.from_env(env)

    def test_env_names_are_documented_prefix(self) -> None:
        """环境变量名统一以 APNS_ 前缀，避免与使用方其它变量撞名。"""
        for name in (ENV_KEY_ID, ENV_TEAM_ID, ENV_BUNDLE_ID, ENV_KEY_PATH, ENV_KEY_PEM):
            assert name.startswith("APNS_")
