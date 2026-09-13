"""APNs reason 解析与错误分类的测试（纯标准库）。"""

from __future__ import annotations

import pytest

from apns_es256 import (
    ApnsReason,
    ApnsResponse,
    ErrorClass,
    classify,
    parse_reason,
)


class TestParseReason:
    def test_known_reason(self) -> None:
        assert parse_reason("BadDeviceToken") is ApnsReason.BAD_DEVICE_TOKEN

    def test_unregistered(self) -> None:
        assert parse_reason("Unregistered") is ApnsReason.UNREGISTERED

    def test_none_returns_none(self) -> None:
        assert parse_reason(None) is None

    def test_empty_returns_none(self) -> None:
        assert parse_reason("") is None
        assert parse_reason("   ") is None

    def test_whitespace_trimmed(self) -> None:
        assert parse_reason("  BadDeviceToken  ") is ApnsReason.BAD_DEVICE_TOKEN

    def test_unknown_reason_maps_to_unknown_not_raise(self) -> None:
        """Apple 加了新 reason 也不能让调用方崩。"""
        assert parse_reason("SomeBrandNewReason") is ApnsReason.UNKNOWN

    def test_case_sensitive(self) -> None:
        # APNs 是精确匹配；大小写不符应归为 UNKNOWN 而非猜
        assert parse_reason("baddevicetoken") is ApnsReason.UNKNOWN


class TestClassify:
    @pytest.mark.parametrize(
        "reason,expected",
        [
            (ApnsReason.UNREGISTERED, ErrorClass.UNREGISTERED),
            (ApnsReason.BAD_DEVICE_TOKEN, ErrorClass.TOKEN_MISMATCH),
            (ApnsReason.DEVICE_TOKEN_NOT_FOR_TOPIC, ErrorClass.TOKEN_MISMATCH),
            (ApnsReason.TOPIC_MISMATCH, ErrorClass.TOKEN_MISMATCH),
            (ApnsReason.INVALID_PROVIDER_TOKEN, ErrorClass.AUTH),
            (ApnsReason.EXPIRED_PROVIDER_TOKEN, ErrorClass.AUTH),
            (ApnsReason.MISSING_PROVIDER_TOKEN, ErrorClass.AUTH),
            (ApnsReason.PAYLOAD_TOO_LARGE, ErrorClass.BAD_REQUEST),
            (ApnsReason.BAD_TOPIC, ErrorClass.BAD_REQUEST),
            (ApnsReason.INTERNAL_SERVER_ERROR, ErrorClass.RETRYABLE),
            (ApnsReason.SERVICE_UNAVAILABLE, ErrorClass.RETRYABLE),
            (ApnsReason.SHUTDOWN, ErrorClass.RETRYABLE),
            (ApnsReason.TOO_MANY_REQUESTS, ErrorClass.THROTTLED),
            (ApnsReason.TOO_MANY_PROVIDER_TOKEN_REQUESTS, ErrorClass.THROTTLED),
        ],
    )
    def test_classification(self, reason: ApnsReason, expected: ErrorClass) -> None:
        assert classify(reason) is expected

    def test_accepts_raw_string(self) -> None:
        assert classify("Unregistered") is ErrorClass.UNREGISTERED

    def test_none_is_unknown(self) -> None:
        assert classify(None) is ErrorClass.UNKNOWN

    def test_unknown_string(self) -> None:
        assert classify("Nonsense") is ErrorClass.UNKNOWN


class TestApnsResponse:
    def test_success(self) -> None:
        response = ApnsResponse(status=200, apns_id="abc")
        assert response.ok
        assert not response.retryable

    def test_200_with_reason_is_failure(self) -> None:
        """理论上不该出现，但真出现时必须当失败处理。"""
        response = ApnsResponse(status=200, reason=ApnsReason.BAD_DEVICE_TOKEN)
        assert not response.ok

    def test_bad_device_token(self) -> None:
        response = ApnsResponse(status=400, reason=ApnsReason.BAD_DEVICE_TOKEN)
        assert not response.ok
        assert response.error_class is ErrorClass.TOKEN_MISMATCH
        assert not response.retryable

    def test_unregistered_with_timestamp(self) -> None:
        response = ApnsResponse(
            status=410, reason=ApnsReason.UNREGISTERED, timestamp=1700000000
        )
        assert response.error_class is ErrorClass.UNREGISTERED
        assert response.timestamp == 1700000000

    def test_retryable_server_error(self) -> None:
        response = ApnsResponse(status=503, reason=ApnsReason.SERVICE_UNAVAILABLE)
        assert response.retryable

    def test_throttled_is_retryable(self) -> None:
        response = ApnsResponse(status=429, reason=ApnsReason.TOO_MANY_REQUESTS)
        assert response.retryable

    @pytest.mark.parametrize(
        "status,expected",
        [
            (500, ErrorClass.RETRYABLE),
            (502, ErrorClass.RETRYABLE),
            (503, ErrorClass.RETRYABLE),
            (504, ErrorClass.RETRYABLE),
            (429, ErrorClass.THROTTLED),
            (403, ErrorClass.AUTH),
            (400, ErrorClass.BAD_REQUEST),
            (410, ErrorClass.UNREGISTERED),
            (418, ErrorClass.UNKNOWN),
        ],
    )
    def test_status_only_fallback(self, status: int, expected: ErrorClass) -> None:
        """没有 reason 时（例如网关返回 HTML）按状态码退化判断。"""
        assert ApnsResponse(status=status).error_class is expected


class TestReasonEnumCompleteness:
    def test_all_reasons_classified(self) -> None:
        """每个枚举成员都必须有分类，不能漏。"""
        for reason in ApnsReason:
            assert classify(reason) is not None

    def test_documented_values_present(self) -> None:
        """抽查 APNs 文档里的关键 reason 是否都在枚举里。"""
        for value in (
            "BadDeviceToken",
            "DeviceTokenNotForTopic",
            "Unregistered",
            "InvalidProviderToken",
            "MissingProviderToken",
            "ExpiredProviderToken",
            "PayloadTooLarge",
            "TooManyProviderTokenUpdates",
            "TooManyRequests",
            "InternalServerError",
            "ServiceUnavailable",
            "Shutdown",
        ):
            assert value in {r.value for r in ApnsReason}, value
