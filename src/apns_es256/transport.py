"""HTTP/2 传输层（抽取自源实现的 ``_post`` 中 ``httpx.Client`` 部分）。

抽取说明
--------
源实现是::

    with httpx.Client(http2=True, timeout=30.0) as client:
        response = client.post(url, headers=headers, json=payload)

即**每次请求新建一个 client**（每条推送都重新建连，无连接池复用），且把
``except Exception`` 一把抓后转成字符串错误。本模块改为：

* 抽象出 :class:`Transport` 协议，使客户端的回落/重试逻辑可脱离网络做单元测试
  （本仓库测试全部走 stub，不联网）；
* 默认实现 :class:`HttpxTransport` **复用一个长生命周期 client**（连接复用），
  这是有意的行为改进；
* 主动探测 ``h2``：APNs 只接受 HTTP/2，缺 ``h2`` 时 httpx 会**静默退回 HTTP/1.1**，
  请求必然失败且报错难懂，所以这里直接给出可操作的提示；
* 区分超时/连接失败等可重试情形，而不是一律降级为字符串。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Protocol, runtime_checkable

from .errors import ApnsTransportError


@dataclass(frozen=True)
class TransportRequest:
    """一次 APNs 请求所需的全部信息。"""

    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes
    timeout: float


@dataclass(frozen=True)
class TransportResponse:
    """传输层归一化后的响应。"""

    status: int
    headers: Mapping[str, str] = field(default_factory=dict)
    body: bytes = b""

    def header(self, name: str) -> str | None:
        """按名字取响应头（不区分大小写）。"""
        target = name.lower()
        for key, value in self.headers.items():
            if key.lower() == target:
                return value
        return None


@runtime_checkable
class Transport(Protocol):
    """传输层协议：实现 ``send`` 即可被 :class:`ApnsClient` 使用。"""

    def send(self, request: TransportRequest) -> TransportResponse:
        ...

    def close(self) -> None:
        ...


class HttpxTransport:
    """基于 ``httpx`` 的 HTTP/2 实现。"""

    def __init__(
        self,
        *,
        http2: bool = True,
        verify: bool = True,
        client: object | None = None,
    ) -> None:
        self._owns_client = client is None
        if client is not None:
            self._client = client
            return

        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - 取决于环境
            raise ApnsTransportError(
                "需要 httpx：pip install 'apns-es256[httpx]'", retryable=False
            ) from exc

        if http2:
            try:
                import h2  # noqa: F401
            except ImportError as exc:
                raise ApnsTransportError(
                    "APNs 要求 HTTP/2，但缺少 h2：pip install 'apns-es256[http2]'"
                    "（等价于 httpx[http2]）",
                    retryable=False,
                ) from exc

        self._client = httpx.Client(http2=http2, verify=verify)

    def send(self, request: TransportRequest) -> TransportResponse:
        import httpx

        try:
            response = self._client.request(  # type: ignore[attr-defined]
                request.method,
                request.url,
                headers=dict(request.headers),
                content=request.body,
                timeout=request.timeout,
            )
        except httpx.TimeoutException as exc:
            raise ApnsTransportError(f"APNs 请求超时: {exc}", retryable=True) from exc
        except httpx.TransportError as exc:
            raise ApnsTransportError(f"APNs 连接失败: {exc}", retryable=True) from exc
        except Exception as exc:  # noqa: BLE001 - 兜底并保留可重试语义
            raise ApnsTransportError(f"APNs 请求异常: {exc}", retryable=True) from exc

        return TransportResponse(
            status=response.status_code,
            headers={k.lower(): v for k, v in response.headers.items()},
            body=response.content,
        )

    def close(self) -> None:
        if self._owns_client:
            closer = getattr(self._client, "close", None)
            if callable(closer):
                closer()

    def __enter__(self) -> "HttpxTransport":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
