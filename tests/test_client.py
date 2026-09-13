"""ApnsClient 行为测试：URL/头部组装、回落、重试、迁移兼容。

**全部离线**：客户端只与 :class:`StubTransport`（或故意抛错的假传输层）交互，
不会有任何真实 socket 连接，也永远不会访问 Apple 端点。
"""

from __future__ import annotations

import json

import pytest

from apns_es256 import (
    ApnsClient,
    ApnsConfig,
    ApnsDeliveryError,
    ApnsEnvironment,
    ApnsReason,
    ApnsTransportError,
    ErrorClass,
    MAX_PAYLOAD_BYTES,
    build_alert_payload,
    validate_device_token,
)
from apns_es256.transport import TransportRequest, TransportResponse

from _stubs import (
    FAKE_BUNDLE_ID,
    FAKE_DEVICE_TOKEN,
    StaticTokenProvider,
    StubTransport,
    assert_is_transport,
    make_config,
    make_response,
    make_test_key,
)

SANDBOX = "https://api.sandbox.push.apple.com"
PRODUCTION = "https://api.push.apple.com"


@pytest.fixture
def tokens() -> StaticTokenProvider:
    return StaticTokenProvider("stub.jwt.token")


def _client(config, transport, tokens, **kwargs) -> ApnsClient:
    sleeps: list[float] = []
    kwargs.setdefault("sleep", sleeps.append)
    client = ApnsClient(config, transport=transport, token_provider=tokens, **kwargs)
    client._test_sleeps = sleeps  # type: ignore[attr-defined]
    return client


def _cfg(tmp_path, **overrides) -> ApnsConfig:
    _, key_path = make_test_key(tmp_path)
    return make_config(key_path, **overrides)


class TestProtocolCompliance:
    def test_stub_satisfies_transport_protocol(self) -> None:
        assert_is_transport(StubTransport())

    def test_injected_transport_not_closed(self, config, tokens) -> None:
        transport = StubTransport()
        _client(config, transport, tokens).close()
        assert transport.closed is False


class TestRequestConstruction:
    """URL 与头部形制必须与源实现一致。"""

    def test_url_shape(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            FAKE_DEVICE_TOKEN, {"aps": {"alert": "hi"}}
        )
        assert stub_transport.urls == [f"{PRODUCTION}/3/device/{FAKE_DEVICE_TOKEN}"]

    def test_method_is_post(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(FAKE_DEVICE_TOKEN, {"aps": {}})
        assert stub_transport.requests[0].method == "POST"

    def test_headers_match_source(self, config, stub_transport, tokens) -> None:
        """源实现头集合：authorization/apns-topic/apns-push-type/apns-priority/content-type"""
        _client(config, stub_transport, tokens).send(
            FAKE_DEVICE_TOKEN, {"aps": {"alert": "hi"}}
        )
        h = stub_transport.last_headers
        assert h["authorization"] == "bearer stub.jwt.token"
        assert h["apns-topic"] == FAKE_BUNDLE_ID
        assert h["apns-push-type"] == "alert"
        assert h["apns-priority"] == "10"
        assert h["content-type"] == "application/json"

    def test_default_timeout_matches_source(self, config) -> None:
        """源实现写死 timeout=30.0。"""
        assert config.timeout == 30.0

    def test_timeout_passed_to_transport(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(FAKE_DEVICE_TOKEN, {"aps": {}})
        assert stub_transport.requests[0].timeout == 30.0

    def test_topic_defaults_to_bundle_id(self, config, stub_transport, tokens) -> None:
        """源实现：if topic is None: topic = self.bundle_id"""
        _client(config, stub_transport, tokens).send(FAKE_DEVICE_TOKEN, {"aps": {}})
        assert stub_transport.last_headers["apns-topic"] == FAKE_BUNDLE_ID

    def test_topic_override(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}, topic="com.example.other"
        )
        assert stub_transport.last_headers["apns-topic"] == "com.example.other"

    def test_push_type_and_priority(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}, push_type="background", priority=5
        )
        h = stub_transport.last_headers
        assert h["apns-push-type"] == "background"
        assert h["apns-priority"] == "5"

    def test_optional_expiration_and_collapse(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}, expiration=1700000000, collapse_id="chat-42"
        )
        h = stub_transport.last_headers
        assert h["apns-expiration"] == "1700000000"
        assert h["apns-collapse-id"] == "chat-42"

    def test_expiration_zero_is_sent(self, config, stub_transport, tokens) -> None:
        """0 是合法值（只投一次），不能当"未设置"丢掉。"""
        _client(config, stub_transport, tokens).send(FAKE_DEVICE_TOKEN, {"aps": {}}, expiration=0)
        assert stub_transport.last_headers["apns-expiration"] == "0"

    def test_body_is_compact_json(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            FAKE_DEVICE_TOKEN, {"aps": {"alert": "hi"}}
        )
        raw = stub_transport.requests[0].body
        assert json.loads(raw) == {"aps": {"alert": "hi"}}

    def test_body_preserves_unicode(self, config, stub_transport, tokens) -> None:
        """中文必须原样 UTF-8 发送，不转义成 \\uXXXX 撑大体积。"""
        _client(config, stub_transport, tokens).send(
            FAKE_DEVICE_TOKEN, {"aps": {"alert": "你好"}}
        )
        assert "你好".encode("utf-8") in stub_transport.requests[0].body


class TestSendAlert:
    """send_alert 的载荷形状必须与源实现一致。"""

    def test_payload_shape(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send_alert(
            FAKE_DEVICE_TOKEN, "标题", "正文", badge=3, sound="chime"
        )
        body = stub_transport.last_body()
        assert body == {
            "aps": {
                "alert": {"title": "标题", "body": "正文"},
                "badge": 3,
                "sound": "chime",
            }
        }

    def test_push_type_is_alert(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send_alert(FAKE_DEVICE_TOKEN, "t", "b")
        assert stub_transport.last_headers["apns-push-type"] == "alert"

    def test_custom_data_merged_at_top_level(self, config, stub_transport, tokens) -> None:
        """源实现是 aps_payload.update(custom_data) —— 顶层合并，不塞进 aps。"""
        _client(config, stub_transport, tokens).send_alert(
            FAKE_DEVICE_TOKEN, "t", "b", custom_data={"push_type": "message"}
        )
        body = stub_transport.last_body()
        assert body["push_type"] == "message"
        assert "push_type" not in body["aps"]

    def test_defaults(self) -> None:
        assert build_alert_payload(title="t", body="b") == {
            "aps": {"alert": {"title": "t", "body": "b"}, "badge": 0, "sound": "default"}
        }

    def test_none_custom_data_ignored(self) -> None:
        payload = build_alert_payload(title="t", body="b", custom_data=None)
        assert set(payload) == {"aps"}


class TestDeviceTokenValidation:
    """设备令牌会拼进 URL path，必须严格校验以防路径注入（源实现无此校验）。"""

    @pytest.mark.parametrize(
        "bad",
        ["zz" * 32, "abc123", "", "  ", "../../1/device/" + "a" * 48],
    )
    def test_rejects_invalid(self, config, stub_transport, tokens, bad: str) -> None:
        with pytest.raises(Exception):
            _client(config, stub_transport, tokens).send(bad, {"aps": {}})

    def test_rejects_non_string(self, config, stub_transport, tokens) -> None:
        with pytest.raises(Exception, match="必须是字符串"):
            _client(config, stub_transport, tokens).send(12345, {"aps": {}})

    def test_no_request_on_invalid_token(self, config, stub_transport, tokens) -> None:
        with pytest.raises(Exception):
            _client(config, stub_transport, tokens).send("bad", {"aps": {}})
        assert stub_transport.requests == []

    def test_uppercase_normalized(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(FAKE_DEVICE_TOKEN.upper(), {"aps": {}})
        assert stub_transport.urls[0].endswith(FAKE_DEVICE_TOKEN)

    def test_helper_returns_lowercase(self) -> None:
        assert validate_device_token(FAKE_DEVICE_TOKEN.upper()) == FAKE_DEVICE_TOKEN


class TestPayloadValidation:
    def test_rejects_oversized(self, config, stub_transport, tokens) -> None:
        with pytest.raises(Exception, match="超过 APNs 上限"):
            _client(config, stub_transport, tokens).send(
                FAKE_DEVICE_TOKEN, {"aps": {"alert": "x" * 5000}}
            )

    def test_limit_is_4096(self) -> None:
        assert MAX_PAYLOAD_BYTES == 4096

    def test_accepts_just_under_limit(self, config, stub_transport, tokens) -> None:
        base = len(json.dumps({"aps": {"alert": ""}}, separators=(",", ":")))
        result = _client(config, stub_transport, tokens).send(
            FAKE_DEVICE_TOKEN, {"aps": {"alert": "x" * (MAX_PAYLOAD_BYTES - base)}}
        )
        assert result.ok

    def test_rejects_non_mapping(self, config, stub_transport, tokens) -> None:
        with pytest.raises(Exception, match="必须是 dict"):
            _client(config, stub_transport, tokens).send(FAKE_DEVICE_TOKEN, ["nope"])


class TestSandboxFallback:
    """生产端点 BadDeviceToken → 沙箱回落（源实现核心行为）。"""

    def test_falls_back_on_bad_device_token(self, config) -> None:
        transport = StubTransport(
            [
                make_response(400, "BadDeviceToken", apns_id="prod-id"),
                make_response(200, apns_id="sandbox-id"),
            ]
        )
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {"alert": "hi"}}
        )

        assert result.ok
        assert result.fell_back is True
        assert result.environment is ApnsEnvironment.SANDBOX
        assert result.tried == (ApnsEnvironment.PRODUCTION, ApnsEnvironment.SANDBOX)
        assert transport.urls == [
            f"{PRODUCTION}/3/device/{FAKE_DEVICE_TOKEN}",
            f"{SANDBOX}/3/device/{FAKE_DEVICE_TOKEN}",
        ]

    def test_no_fallback_when_disabled(self, tmp_path) -> None:
        config = _cfg(tmp_path, sandbox_fallback=False)
        transport = StubTransport([make_response(400, "BadDeviceToken")])
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        assert not result.ok and result.fell_back is False
        assert len(transport.urls) == 1

    def test_no_fallback_for_unregistered(self, config) -> None:
        """Unregistered 是令牌真失效，不该回落。"""
        transport = StubTransport([make_response(410, "Unregistered", timestamp=1)])
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        assert result.fell_back is False
        assert result.error_class is ErrorClass.UNREGISTERED
        assert len(transport.urls) == 1

    def test_no_reverse_fallback_from_sandbox(self, tmp_path) -> None:
        """源实现用 'sandbox' not in url 守卫；反向回落必须不发生。"""
        config = _cfg(tmp_path, environment=ApnsEnvironment.SANDBOX)
        transport = StubTransport([make_response(400, "BadDeviceToken"), make_response(200)])
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        assert result.fell_back is False
        assert len(transport.urls) == 1
        assert SANDBOX in transport.urls[0]
        assert PRODUCTION not in transport.urls[0]

    def test_fallback_only_once(self, config) -> None:
        transport = StubTransport([make_response(400, "BadDeviceToken")])
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        assert result.fell_back is True
        assert len(transport.urls) == 2

    def test_fallback_preserves_token_and_body(self, config) -> None:
        transport = StubTransport([make_response(400, "BadDeviceToken"), make_response(200)])
        _client(config, transport, StaticTokenProvider("tok")).send(
            FAKE_DEVICE_TOKEN, {"aps": {"alert": "hi"}}
        )
        first, second = transport.requests
        assert first.url.split("/3/device/")[1] == second.url.split("/3/device/")[1]
        assert first.body == second.body
        assert first.headers["apns-topic"] == second.headers["apns-topic"]

    def test_start_directly_in_sandbox(self, tmp_path) -> None:
        """对应源实现 use_sandbox=True 的分支。"""
        config = _cfg(tmp_path, environment=ApnsEnvironment.SANDBOX)
        transport = StubTransport([make_response(200)])
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        assert result.ok and result.environment is ApnsEnvironment.SANDBOX
        assert transport.urls[0].startswith(SANDBOX)

    def test_environment_override_per_call(self, config) -> None:
        transport = StubTransport([make_response(200)])
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}, environment=ApnsEnvironment.SANDBOX
        )
        assert result.environment is ApnsEnvironment.SANDBOX


class TestRetrySemantics:
    """源实现无重试（max_retries 默认 0）；这里验证新增能力的边界。"""

    def test_default_is_no_retry_matching_source(self, config) -> None:
        assert config.max_retries == 0
        transport = StubTransport([make_response(503, "ServiceUnavailable")])
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        assert result.attempts == 1
        assert len(transport.urls) == 1

    def test_retries_when_enabled(self, tmp_path) -> None:
        config = _cfg(tmp_path, max_retries=2, retry_backoff=0.5)
        transport = StubTransport([make_response(503, "ServiceUnavailable"), make_response(200)])
        client = _client(config, transport, StaticTokenProvider())
        result = client.send(FAKE_DEVICE_TOKEN, {"aps": {}})
        assert result.ok and result.attempts == 2
        assert client._test_sleeps == [0.5]  # type: ignore[attr-defined]

    def test_exponential_backoff(self, tmp_path) -> None:
        config = _cfg(tmp_path, max_retries=2, retry_backoff=0.5)
        transport = StubTransport(
            [
                make_response(500, "InternalServerError"),
                make_response(503, "ServiceUnavailable"),
                make_response(200),
            ]
        )
        client = _client(config, transport, StaticTokenProvider())
        client.send(FAKE_DEVICE_TOKEN, {"aps": {}})
        assert client._test_sleeps == [0.5, 1.0]  # type: ignore[attr-defined]

    def test_exhausts_retries(self, tmp_path) -> None:
        config = _cfg(tmp_path, max_retries=2)
        transport = StubTransport([make_response(503, "ServiceUnavailable")])
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        assert result.attempts == 3
        assert result.retryable

    def test_no_retry_on_bad_request(self, tmp_path) -> None:
        config = _cfg(tmp_path, max_retries=3)
        transport = StubTransport([make_response(400, "PayloadTooLarge")])
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        assert result.attempts == 1

    def test_transport_error_retried(self, tmp_path) -> None:
        config = _cfg(tmp_path, max_retries=1)

        class Flaky(StubTransport):
            def __init__(self) -> None:
                super().__init__()
                self.calls = 0

            def send(self, request: TransportRequest) -> TransportResponse:
                self.calls += 1
                if self.calls == 1:
                    raise ApnsTransportError("reset", retryable=True)
                return make_response(200)

        result = _client(config, Flaky(), StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        assert result.ok and result.attempts == 2

    def test_non_retryable_transport_error_not_retried(self, tmp_path) -> None:
        config = _cfg(tmp_path, max_retries=3)

        class Dead(StubTransport):
            def __init__(self) -> None:
                super().__init__()
                self.calls = 0

            def send(self, request: TransportRequest) -> TransportResponse:
                self.calls += 1
                raise ApnsTransportError("missing h2", retryable=False)

        transport = Dead()
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        assert not result.ok and transport.calls == 1


class TestProviderTokenRecovery:
    def test_invalidates_on_expired_token(self, tmp_path) -> None:
        config = _cfg(tmp_path, max_retries=0)
        transport = StubTransport([make_response(403, "ExpiredProviderToken"), make_response(200)])
        tokens = StaticTokenProvider()
        result = _client(config, transport, tokens).send(FAKE_DEVICE_TOKEN, {"aps": {}})
        assert result.ok
        assert tokens.invalidations == 1

    def test_missing_token_fails_like_source(self, config) -> None:
        """源实现：拿不到 token → {'success': False, 'error': 'Failed to generate auth token'}"""
        transport = StubTransport([make_response(200)])
        tokens = StaticTokenProvider(token=None)
        result = _client(config, transport, tokens).send(FAKE_DEVICE_TOKEN, {"aps": {}})
        assert not result.ok
        assert result.response.status == 0
        assert transport.requests == [], "拿不到 token 就不该发请求"


class TestResponseParsing:
    def test_non_json_body_tolerated(self, config) -> None:
        transport = StubTransport(
            [TransportResponse(status=502, headers={"content-type": "text/html"}, body=b"<html>x</html>")]
        )
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        assert not result.ok
        assert result.response.reason is None
        assert result.error_class is ErrorClass.RETRYABLE

    def test_empty_body_success(self, config) -> None:
        transport = StubTransport([TransportResponse(status=200, body=b"")])
        assert _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        ).ok

    def test_apns_id_from_header(self, config) -> None:
        transport = StubTransport([make_response(200, apns_id="abc-123")])
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        assert result.apns_id == "abc-123"

    def test_unknown_reason_tolerated(self, config) -> None:
        transport = StubTransport([make_response(400, "BrandNewReason")])
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        assert result.response.reason is ApnsReason.UNKNOWN


class TestMigrationCompatibility:
    """调用方从源实现迁移时，字典式取值应仍然可用。"""

    def test_as_dict_success_matches_source(self, config, stub_transport, tokens) -> None:
        result = _client(config, stub_transport, tokens).send(FAKE_DEVICE_TOKEN, {"aps": {}})
        assert result.as_dict() == {"success": True}

    def test_as_dict_failure_shape(self, config) -> None:
        transport = StubTransport([make_response(400, "BadDeviceToken"), make_response(400, "BadDeviceToken")])
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        d = result.as_dict()
        assert d["success"] is False
        assert d["status_code"] == 400
        assert d["error"] == "BadDeviceToken"

    def test_getitem_and_get(self, config, stub_transport, tokens) -> None:
        result = _client(config, stub_transport, tokens).send(FAKE_DEVICE_TOKEN, {"aps": {}})
        assert result["success"] is True
        assert result.get("success") is True
        assert result.get("missing", "dflt") == "dflt"

    def test_raise_on_error(self, config) -> None:
        transport = StubTransport([make_response(410, "Unregistered")])
        with pytest.raises(ApnsDeliveryError) as excinfo:
            _client(config, transport, StaticTokenProvider()).send(
                FAKE_DEVICE_TOKEN, {"aps": {}}, raise_on_error=True
            )
        assert excinfo.value.result.response.reason is ApnsReason.UNREGISTERED


class TestSendMany:
    def test_sends_to_each(self, config, stub_transport, tokens) -> None:
        other = "a" * 64
        results = _client(config, stub_transport, tokens).send_many(
            [FAKE_DEVICE_TOKEN, other], {"aps": {}}
        )
        assert len(results) == 2 and all(r.ok for r in results)
        assert stub_transport.urls[1].endswith(other)

    def test_one_failure_does_not_stop_others(self, config) -> None:
        transport = StubTransport([make_response(410, "Unregistered"), make_response(200)])
        results = _client(config, transport, StaticTokenProvider()).send_many(
            [FAKE_DEVICE_TOKEN, "b" * 64], {"aps": {}}
        )
        assert results[0].ok is False and results[1].ok is True


class TestNoNetworkGuarantee:
    def test_full_cycle_cannot_open_sockets(self, config, stub_transport, tokens, monkeypatch) -> None:
        """把 socket 彻底封死后完整流程仍能跑通 —— 机制上保证不联网。"""
        import socket

        class Forbidden:
            def __init__(self, *a, **k):
                raise AssertionError("测试期间禁止创建 socket")

        monkeypatch.setattr(socket, "socket", Forbidden)
        monkeypatch.setattr(socket, "create_connection", Forbidden)

        result = _client(config, stub_transport, tokens).send(
            FAKE_DEVICE_TOKEN, {"aps": {"alert": "hi"}}
        )
        assert result.ok

    def test_fallback_cycle_cannot_open_sockets(self, config, monkeypatch) -> None:
        import socket

        class Forbidden:
            def __init__(self, *a, **k):
                raise AssertionError("测试期间禁止创建 socket")

        monkeypatch.setattr(socket, "socket", Forbidden)
        transport = StubTransport([make_response(400, "BadDeviceToken"), make_response(200)])
        result = _client(config, transport, StaticTokenProvider()).send(
            FAKE_DEVICE_TOKEN, {"aps": {}}
        )
        assert result.fell_back is True

    def test_default_transport_requires_h2(self, monkeypatch) -> None:
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *a, **k):
            if name == "h2":
                raise ImportError("simulated missing h2")
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        from apns_es256.transport import HttpxTransport

        with pytest.raises(ApnsTransportError, match="HTTP/2"):
            HttpxTransport()

    def test_client_does_not_import_httpx_directly(self) -> None:
        import inspect

        from apns_es256 import client as client_module

        source = inspect.getsource(client_module)
        assert "import httpx" not in source
        assert "socket" not in source
