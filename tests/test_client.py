"""ApnsClient 的行为测试：URL 组装、回落、重试、令牌失效自愈。

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
)
from apns_es256.transport import TransportRequest, TransportResponse

from _stubs import (
    FAKE_BUNDLE_ID,
    FAKE_DEVICE_TOKEN,
    StaticTokenProvider,
    StubTransport,
    assert_is_transport,
    make_response,
)

SANDBOX = "https://api.sandbox.push.apple.com"
PRODUCTION = "https://api.push.apple.com"


@pytest.fixture
def tokens() -> StaticTokenProvider:
    return StaticTokenProvider("stub.jwt.token")


def _client(
    config: ApnsConfig,
    transport: StubTransport,
    tokens: StaticTokenProvider,
    **kwargs: object,
) -> ApnsClient:
    sleeps: list[float] = []
    kwargs.setdefault("sleep", sleeps.append)
    client = ApnsClient(config, transport=transport, token_provider=tokens, **kwargs)  # type: ignore[arg-type]
    client._test_sleeps = sleeps  # type: ignore[attr-defined]
    return client


class TestProtocolCompliance:
    def test_stub_satisfies_transport_protocol(self) -> None:
        assert_is_transport(StubTransport())

    def test_client_does_not_own_injected_transport(
        self, config: ApnsConfig, tokens: StaticTokenProvider
    ) -> None:
        """外部注入的传输层不该被客户端关闭（生命周期归调用方）。"""
        transport = StubTransport()
        client = _client(config, transport, tokens)
        client.close()
        assert transport.closed is False


class TestRequestConstruction:
    def test_url_uses_production_host(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {"alert": "hi"}}
        )
        assert stub_transport.urls == [f"{PRODUCTION}/3/device/{FAKE_DEVICE_TOKEN}"]

    def test_method_is_post(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {"alert": "hi"}}
        )
        assert stub_transport.requests[0].method == "POST"

    def test_headers(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {"alert": "hi"}}
        )
        headers = stub_transport.last_headers
        assert headers["authorization"] == "bearer stub.jwt.token"
        assert headers["apns-topic"] == FAKE_BUNDLE_ID
        assert headers["apns-push-type"] == "alert"
        assert headers["apns-priority"] == "10"
        assert headers["content-type"] == "application/json"

    def test_optional_headers(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN,
            payload={"aps": {"alert": "hi"}},
            push_type="background",
            priority=5,
            expiration=1700000000,
            collapse_id="chat-42",
        )
        headers = stub_transport.last_headers
        assert headers["apns-push-type"] == "background"
        assert headers["apns-priority"] == "5"
        assert headers["apns-expiration"] == "1700000000"
        assert headers["apns-collapse-id"] == "chat-42"

    def test_expiration_zero_is_sent(self, config, stub_transport, tokens) -> None:
        """0 是合法值（只投一次），不能被当成"未设置"而丢掉。"""
        _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}, expiration=0
        )
        assert stub_transport.last_headers["apns-expiration"] == "0"

    def test_topic_override(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN,
            payload={"aps": {}},
            topic="com.example.other",
        )
        assert stub_transport.last_headers["apns-topic"] == "com.example.other"

    def test_extra_headers(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN,
            payload={"aps": {}},
            extra_headers={"apns-id": "custom-id"},
        )
        assert stub_transport.last_headers["apns-id"] == "custom-id"

    def test_body_is_compact_json(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {"alert": "hi"}}
        )
        raw = stub_transport.requests[0].body
        assert b" " not in raw, "载荷必须是紧凑 JSON"
        assert json.loads(raw) == {"aps": {"alert": "hi"}}

    def test_body_preserves_unicode(self, config, stub_transport, tokens) -> None:
        """中文必须原样以 UTF-8 发送，不能被转义成 \\uXXXX 撑大体积。"""
        _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {"alert": "你好"}}
        )
        assert "你好".encode("utf-8") in stub_transport.requests[0].body

    def test_token_from_provider(self, config, stub_transport) -> None:
        tokens = StaticTokenProvider("custom.token.here")
        _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert stub_transport.last_headers["authorization"] == "bearer custom.token.here"


class TestDeviceTokenValidation:
    """设备令牌会拼进 URL path，必须严格校验以防路径注入。"""

    def test_rejects_non_hex(self, config, stub_transport, tokens) -> None:
        with pytest.raises(Exception, match="64 位十六进制"):
            _client(config, stub_transport, tokens).send(
                device_token="zz" * 32, payload={"aps": {}}
            )

    def test_rejects_short(self, config, stub_transport, tokens) -> None:
        with pytest.raises(Exception, match="64 位十六进制"):
            _client(config, stub_transport, tokens).send(
                device_token="abc123", payload={"aps": {}}
            )

    def test_rejects_empty(self, config, stub_transport, tokens) -> None:
        with pytest.raises(Exception, match="不能为空"):
            _client(config, stub_transport, tokens).send(
                device_token="", payload={"aps": {}}
            )

    def test_rejects_path_traversal(self, config, stub_transport, tokens) -> None:
        """这是校验存在的核心原因。"""
        with pytest.raises(Exception, match="64 位十六进制"):
            _client(config, stub_transport, tokens).send(
                device_token="../../1/device/" + "a" * 48, payload={"aps": {}}
            )

    def test_rejects_non_string(self, config, stub_transport, tokens) -> None:
        with pytest.raises(Exception, match="必须是字符串"):
            _client(config, stub_transport, tokens).send(
                device_token=12345, payload={"aps": {}}  # type: ignore[arg-type]
            )

    def test_no_request_sent_on_invalid_token(self, config, stub_transport, tokens) -> None:
        with pytest.raises(Exception):
            _client(config, stub_transport, tokens).send(
                device_token="bad", payload={"aps": {}}
            )
        assert stub_transport.requests == [], "令牌非法时不该发出任何请求"

    def test_uppercase_accepted_and_lowercased(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN.upper(), payload={"aps": {}}
        )
        assert stub_transport.urls[0].endswith(FAKE_DEVICE_TOKEN)


class TestPayloadValidation:
    def test_rejects_oversized_payload(self, config, stub_transport, tokens) -> None:
        big = {"aps": {"alert": "x" * 5000}}
        with pytest.raises(Exception, match="超过 APNs 上限"):
            _client(config, stub_transport, tokens).send(
                device_token=FAKE_DEVICE_TOKEN, payload=big
            )

    def test_accepts_payload_just_under_limit(self, config, stub_transport, tokens) -> None:
        body_len = len(json.dumps({"aps": {"alert": ""}}, separators=(",", ":")))
        filler = "x" * (4090 - body_len)
        result = _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {"alert": filler}}
        )
        assert result.ok

    def test_rejects_non_mapping(self, config, stub_transport, tokens) -> None:
        with pytest.raises(Exception, match="必须是 dict"):
            _client(config, stub_transport, tokens).send(
                device_token=FAKE_DEVICE_TOKEN, payload=["not", "a", "dict"]  # type: ignore[arg-type]
            )

    def test_rejects_unserializable(self, config, stub_transport, tokens) -> None:
        with pytest.raises(Exception, match="无法序列化"):
            _client(config, stub_transport, tokens).send(
                device_token=FAKE_DEVICE_TOKEN, payload={"aps": {"n": object()}}
            )


class TestSandboxFallback:
    """生产端点 BadDeviceToken → 沙箱回落。"""

    def test_falls_back_on_bad_device_token(self, config) -> None:
        transport = StubTransport(
            [
                make_response(400, "BadDeviceToken", apns_id="prod-id"),
                make_response(200, apns_id="sandbox-id"),
            ]
        )
        tokens = StaticTokenProvider()
        result = _client(config, transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {"alert": "hi"}}
        )

        assert result.ok
        assert result.fell_back is True
        assert result.environment is ApnsEnvironment.SANDBOX
        assert result.tried == (ApnsEnvironment.PRODUCTION, ApnsEnvironment.SANDBOX)
        assert result.attempts == 2
        assert transport.urls == [
            f"{PRODUCTION}/3/device/{FAKE_DEVICE_TOKEN}",
            f"{SANDBOX}/3/device/{FAKE_DEVICE_TOKEN}",
        ]

    def test_no_fallback_when_disabled(self, config) -> None:
        transport = StubTransport([make_response(400, "BadDeviceToken")])
        disabled = ApnsConfig(
            key_id=config.key_id,
            team_id=config.team_id,
            bundle_id=config.bundle_id,
            key_pem=config.key_pem,
            sandbox_fallback=False,
        )
        result = _client(disabled, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )

        assert not result.ok
        assert result.fell_back is False
        assert result.attempts == 1
        assert len(transport.urls) == 1

    def test_no_fallback_for_unregistered(self, config) -> None:
        """Unregistered 是令牌真失效，不该回落，应让调用方删令牌。"""
        transport = StubTransport(
            [make_response(410, "Unregistered", timestamp=1700000000)]
        )
        result = _client(config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )

        assert not result.ok
        assert result.fell_back is False
        assert result.error_class is ErrorClass.UNREGISTERED
        assert result.response.timestamp == 1700000000
        assert len(transport.urls) == 1

    def test_no_fallback_from_sandbox_to_production(self) -> None:
        """反向回落没有意义，必须完全不发生。"""
        sandbox_config = ApnsConfig(
            key_id="ABCDE12345",
            team_id="ZYXWV98765",
            bundle_id="com.example.app",
            key_pem="placeholder",
            environment=ApnsEnvironment.SANDBOX,
        )
        transport = StubTransport(
            [
                make_response(400, "BadDeviceToken"),
                make_response(200),  # 若发生反向回落就会被用掉
            ]
        )
        result = _client(sandbox_config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )

        assert not result.ok
        assert result.fell_back is False
        assert len(transport.urls) == 1
        assert SANDBOX in transport.urls[0]
        assert PRODUCTION not in transport.urls[0]

    def test_fallback_only_once(self, config) -> None:
        """沙箱也回 BadDeviceToken 时不能来回横跳。"""
        transport = StubTransport([make_response(400, "BadDeviceToken")])
        result = _client(config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert result.fell_back is True
        assert result.attempts == 2
        assert len(transport.urls) == 2  # 生产 + 沙箱各一次，就结束

    def test_fallback_keeps_same_token_and_headers(self, config) -> None:
        transport = StubTransport(
            [make_response(400, "BadDeviceToken"), make_response(200)]
        )
        _client(config, transport, StaticTokenProvider("tok")).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {"alert": "hi"}}
        )
        first, second = transport.requests
        assert first.url.split("/3/device/")[1] == second.url.split("/3/device/")[1]
        assert first.body == second.body
        assert first.headers["apns-topic"] == second.headers["apns-topic"]

    def test_start_directly_in_sandbox(self, config) -> None:
        sandbox_config = ApnsConfig(
            key_id="ABCDE12345",
            team_id="ZYXWV98765",
            bundle_id="com.example.app",
            key_pem="placeholder",
            environment=ApnsEnvironment.SANDBOX,
        )
        transport = StubTransport([make_response(200)])
        result = _client(sandbox_config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert result.ok
        assert result.environment is ApnsEnvironment.SANDBOX
        assert transport.urls[0].startswith(SANDBOX)

    def test_environment_override_per_call(self, config) -> None:
        transport = StubTransport([make_response(200)])
        result = _client(config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN,
            payload={"aps": {}},
            environment=ApnsEnvironment.SANDBOX,
        )
        assert result.environment is ApnsEnvironment.SANDBOX
        assert transport.urls[0].startswith(SANDBOX)


class TestRetrySemantics:
    def test_retries_on_service_unavailable(self, config) -> None:
        transport = StubTransport(
            [
                make_response(503, "ServiceUnavailable"),
                make_response(200),
            ]
        )
        client = _client(config, transport, StaticTokenProvider())
        result = client.send(device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}})

        assert result.ok
        assert result.attempts == 2
        assert client._test_sleeps == [0.5]  # type: ignore[attr-defined]

    def test_exponential_backoff(self, config) -> None:
        transport = StubTransport(
            [
                make_response(500, "InternalServerError"),
                make_response(503, "ServiceUnavailable"),
                make_response(200),
            ]
        )
        client = _client(config, transport, StaticTokenProvider())
        client.send(device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}})

        # 第一次退避 0.5*2^0，第二次 0.5*2^1
        assert client._test_sleeps == [0.5, 1.0]  # type: ignore[attr-defined]

    def test_exhausts_retries(self, config) -> None:
        transport = StubTransport([make_response(503, "ServiceUnavailable")])
        result = _client(config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )

        assert not result.ok
        assert result.attempts == 3  # 1 次首发 + max_retries(2)
        assert result.error_class is ErrorClass.RETRYABLE
        assert result.retryable

    def test_no_retry_on_bad_request(self, config) -> None:
        transport = StubTransport([make_response(400, "PayloadTooLarge")])
        result = _client(config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert result.attempts == 1
        assert result.error_class is ErrorClass.BAD_REQUEST
        assert not result.retryable

    def test_no_retry_on_unregistered(self, config) -> None:
        transport = StubTransport([make_response(410, "Unregistered")])
        result = _client(config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert result.attempts == 1

    def test_max_retries_zero(self, config) -> None:
        zero = ApnsConfig(
            key_id=config.key_id,
            team_id=config.team_id,
            bundle_id=config.bundle_id,
            key_pem=config.key_pem,
            max_retries=0,
        )
        transport = StubTransport([make_response(503, "ServiceUnavailable")])
        result = _client(zero, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert result.attempts == 1

    def test_transport_error_is_retried(self, config) -> None:
        class FlakyTransport(StubTransport):
            def __init__(self) -> None:
                super().__init__()
                self.calls = 0

            def send(self, request: TransportRequest) -> TransportResponse:
                self.calls += 1
                if self.calls == 1:
                    raise ApnsTransportError("connection reset", retryable=True)
                return make_response(200)

        transport = FlakyTransport()
        result = _client(config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert result.ok
        assert result.attempts == 2

    def test_non_retryable_transport_error_not_retried(self, config) -> None:
        class DeadTransport(StubTransport):
            def __init__(self) -> None:
                super().__init__()
                self.calls = 0

            def send(self, request: TransportRequest) -> TransportResponse:
                self.calls += 1
                raise ApnsTransportError("missing h2", retryable=False)

        transport = DeadTransport()
        result = _client(config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert not result.ok
        assert transport.calls == 1


class TestProviderTokenRecovery:
    def test_invalidates_and_retries_on_expired_token(self, config) -> None:
        transport = StubTransport(
            [
                make_response(403, "ExpiredProviderToken"),
                make_response(200),
            ]
        )
        tokens = StaticTokenProvider()
        result = _client(config, transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )

        assert result.ok
        assert tokens.invalidations == 1, "必须作废缓存 token 以便重签"
        assert result.attempts == 2

    def test_invalidates_on_invalid_provider_token(self, config) -> None:
        transport = StubTransport(
            [make_response(403, "InvalidProviderToken"), make_response(200)]
        )
        tokens = StaticTokenProvider()
        _client(config, transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert tokens.invalidations == 1

    def test_does_not_invalidate_on_success(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert tokens.invalidations == 0


class TestResponseParsing:
    def test_non_json_body_does_not_crash(self, config) -> None:
        """网关 502 常返回 HTML，必须优雅处理。"""
        transport = StubTransport(
            [
                TransportResponse(
                    status=502,
                    headers={"content-type": "text/html"},
                    body=b"<html>Bad Gateway</html>",
                )
            ]
        )
        result = _client(config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert not result.ok
        assert result.response.reason is None
        assert result.error_class is ErrorClass.RETRYABLE  # 按状态码退化

    def test_empty_body_success(self, config) -> None:
        transport = StubTransport([TransportResponse(status=200, body=b"")])
        result = _client(config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert result.ok

    def test_apns_id_extracted_from_header(self, config) -> None:
        transport = StubTransport([make_response(200, apns_id="abc-123")])
        result = _client(config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert result.apns_id == "abc-123"

    def test_x_apns_id_fallback(self, config) -> None:
        transport = StubTransport(
            [
                TransportResponse(
                    status=200, headers={"x-apns-id": "legacy-123"}, body=b""
                )
            ]
        )
        result = _client(config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert result.apns_id == "legacy-123"

    def test_unknown_reason_tolerated(self, config) -> None:
        transport = StubTransport([make_response(400, "BrandNewReasonFromApple")])
        result = _client(config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert result.response.reason is ApnsReason.UNKNOWN
        assert result.error_class is ErrorClass.UNKNOWN


class TestRaiseOnError:
    def test_raises_delivery_error(self, config) -> None:
        transport = StubTransport([make_response(410, "Unregistered")])
        with pytest.raises(ApnsDeliveryError) as excinfo:
            _client(config, transport, StaticTokenProvider()).send(
                device_token=FAKE_DEVICE_TOKEN,
                payload={"aps": {}},
                raise_on_error=True,
            )
        assert excinfo.value.result.response.reason is ApnsReason.UNREGISTERED

    def test_no_raise_on_success(self, config, stub_transport, tokens) -> None:
        _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}, raise_on_error=True
        )


class TestReasonCallback:
    def test_callback_invoked(self, config) -> None:
        transport = StubTransport([make_response(410, "Unregistered", timestamp=1)])
        seen: list = []
        client = _client(
            config,
            transport,
            StaticTokenProvider(),
            on_reason={ApnsReason.UNREGISTERED: seen.append},
        )
        client.send(device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}})
        assert len(seen) == 1
        assert seen[0].status == 410

    def test_callback_not_invoked_on_success(self, config, stub_transport, tokens) -> None:
        seen: list = []
        client = _client(
            config,
            stub_transport,
            tokens,
            on_reason={ApnsReason.UNREGISTERED: seen.append},
        )
        client.send(device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}})
        assert seen == []


class TestSendMany:
    def test_sends_to_each_token(self, config, stub_transport, tokens) -> None:
        other = "a" * 64
        results = _client(config, stub_transport, tokens).send_many(
            device_tokens=[FAKE_DEVICE_TOKEN, other], payload={"aps": {}}
        )
        assert len(results) == 2
        assert len(stub_transport.urls) == 2
        assert all(r.ok for r in results)
        assert stub_transport.urls[1].endswith(other)

    def test_one_failure_does_not_stop_others(self, config) -> None:
        transport = StubTransport(
            [make_response(410, "Unregistered"), make_response(200)]
        )
        config_noretry = ApnsConfig(
            key_id=config.key_id,
            team_id=config.team_id,
            bundle_id=config.bundle_id,
            key_pem=config.key_pem,
        )
        results = _client(config_noretry, transport, StaticTokenProvider()).send_many(
            device_tokens=[FAKE_DEVICE_TOKEN, "b" * 64], payload={"aps": {}}
        )
        assert results[0].ok is False
        assert results[1].ok is True


class TestNoNetworkGuarantee:
    def test_full_send_cycle_cannot_open_sockets(
        self, config, stub_transport, tokens, monkeypatch
    ) -> None:
        """硬性保证：把 socket 彻底封死后，完整的发送流程仍能跑通。

        这比"我们只用了 stub"更强 —— 即使有某个隐藏分支偷偷联网，这里也会失败。
        """
        import socket

        class ForbiddenSocket:
            def __init__(self, *args, **kwargs):
                raise AssertionError("测试期间禁止创建任何 socket 连接")

        monkeypatch.setattr(socket, "socket", ForbiddenSocket)
        monkeypatch.setattr(socket, "create_connection", ForbiddenSocket)
        monkeypatch.setattr(
            socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("测试期间禁止 DNS 解析")
            )
        )

        result = _client(config, stub_transport, tokens).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {"alert": "hi"}}
        )
        assert result.ok
        assert len(stub_transport.requests) == 1

    def test_full_cycle_cannot_open_sockets_with_sandbox_fallback(
        self, config, monkeypatch
    ) -> None:
        """回落分支（会换一个 host）同样不得联网。"""
        import socket

        class ForbiddenSocket:
            def __init__(self, *args, **kwargs):
                raise AssertionError("测试期间禁止创建任何 socket 连接")

        monkeypatch.setattr(socket, "socket", ForbiddenSocket)
        monkeypatch.setattr(
            socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(
                AssertionError("测试期间禁止 DNS 解析")
            )
        )

        transport = StubTransport(
            [make_response(400, "BadDeviceToken"), make_response(200)]
        )
        result = _client(config, transport, StaticTokenProvider()).send(
            device_token=FAKE_DEVICE_TOKEN, payload={"aps": {}}
        )
        assert result.fell_back is True
        assert len(transport.urls) == 2

    def test_default_transport_requires_httpx(self, monkeypatch) -> None:
        """默认传输层在缺 h2 时必须明确报错，而不是退回 HTTP/1.1 静默失败。"""
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "h2":
                raise ImportError("simulated missing h2")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        from apns_es256.transport import HttpxTransport

        with pytest.raises(ApnsTransportError, match="HTTP/2"):
            HttpxTransport()

    def test_tests_never_touch_socket(self) -> None:
        """本套件的断言基石：客户端只通过注入的传输层发请求。"""
        import inspect

        from apns_es256 import client as client_module

        source = inspect.getsource(client_module)
        # 客户端自身不得直接导入 httpx / 不得开 socket
        assert "import httpx" not in source
        assert "socket" not in source
