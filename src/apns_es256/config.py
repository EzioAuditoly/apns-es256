"""客户端配置。

抽取说明
--------
源实现把端点选择写成构造函数里的 if 分支、把 KeyID/TeamID/bundle id 作为裸参数传入。
本模块保留同样的语义，但：

* 端点常量与 Apple 公开域名一致（可安全开源）；
* 增加**环境变量读取**，使凭据不必出现在代码或配置字面量里；
* 增加参数校验（源实现无校验，错误配置要到 Apple 侧才以 403 暴露）。
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .errors import ApnsConfigError

#: 环境变量名（占位示例，使用方自行设置真实值）
ENV_KEY_ID = "APNS_KEY_ID"
ENV_TEAM_ID = "APNS_TEAM_ID"
ENV_BUNDLE_ID = "APNS_BUNDLE_ID"
ENV_KEY_PATH = "APNS_KEY_PATH"


class ApnsEnvironment(str, Enum):
    """APNs 的两个隔离端点（源实现用 ``use_sandbox: bool`` 表达）。"""

    PRODUCTION = "production"
    SANDBOX = "sandbox"

    @property
    def base_url(self) -> str:
        """该环境对应的主机地址（与源实现写死的两个 URL 完全相同）。"""
        if self is ApnsEnvironment.PRODUCTION:
            return "https://api.push.apple.com"
        return "https://api.sandbox.push.apple.com"


#: 两个公开端点常量
PRODUCTION_HOST = ApnsEnvironment.PRODUCTION.base_url
SANDBOX_HOST = ApnsEnvironment.SANDBOX.base_url


@dataclass
class ApnsConfig:
    """APNs 连接与认证配置。

    :param key_id: ``.p8`` 密钥的 Key ID。默认读 ``APNS_KEY_ID``。
    :param team_id: Apple Developer Team ID。默认读 ``APNS_TEAM_ID``。
    :param bundle_id: App 的 bundle id，作为 ``apns-topic``。默认读 ``APNS_BUNDLE_ID``。
    :param key_path: ``.p8`` 私钥文件路径。默认读 ``APNS_KEY_PATH``。
    :param environment: 起始环境（对应源实现的 ``use_sandbox``）。
    :param sandbox_fallback: 生产端点遇 ``BadDeviceToken`` 时是否自动回落沙箱。
    :param timeout: 单次请求超时秒数（源实现写死 **30.0**）。
    :param max_retries: 可重试错误的额外重试次数（源实现写死 **0**，即不重试）。
    :param retry_backoff: 退避基数秒；第 n 次重试等待 ``retry_backoff * 2**(n-1)``。
    """

    key_id: str = ""
    team_id: str = ""
    bundle_id: str = ""
    key_path: str | None = None
    environment: ApnsEnvironment = ApnsEnvironment.PRODUCTION
    sandbox_fallback: bool = True
    timeout: float = 30.0
    max_retries: int = 0
    retry_backoff: float = 0.5
    extra_headers: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None, **overrides: object) -> "ApnsConfig":
        """从环境变量组装配置，``overrides`` 里的显式值优先。"""
        source = os.environ if env is None else env
        values: dict[str, object] = {
            "key_id": source.get(ENV_KEY_ID, ""),
            "team_id": source.get(ENV_TEAM_ID, ""),
            "bundle_id": source.get(ENV_BUNDLE_ID, ""),
            "key_path": source.get(ENV_KEY_PATH) or None,
        }
        values.update(overrides)
        return cls(**values)  # type: ignore[arg-type]

    def __post_init__(self) -> None:
        if isinstance(self.environment, str):
            try:
                self.environment = ApnsEnvironment(self.environment)
            except ValueError as exc:
                raise ApnsConfigError(
                    f"environment 只能是 'production' 或 'sandbox'，收到 {self.environment!r}"
                ) from exc

        if not self.key_id or not self.key_id.strip():
            raise ApnsConfigError(f"缺少 key_id（可用环境变量 {ENV_KEY_ID}）")
        if not self.team_id or not self.team_id.strip():
            raise ApnsConfigError(f"缺少 team_id（可用环境变量 {ENV_TEAM_ID}）")
        if not self.bundle_id or not self.bundle_id.strip():
            raise ApnsConfigError(f"缺少 bundle_id（作为 apns-topic，可用环境变量 {ENV_BUNDLE_ID}）")
        if not self.key_path:
            raise ApnsConfigError(f"缺少私钥路径（可用环境变量 {ENV_KEY_PATH}）")
        if not Path(self.key_path).is_file():
            raise ApnsConfigError(f"私钥文件不存在: {self.key_path}")

        if self.timeout <= 0:
            raise ApnsConfigError("timeout 必须为正数")
        if self.max_retries < 0:
            raise ApnsConfigError("max_retries 不能为负")
        if self.retry_backoff < 0:
            raise ApnsConfigError("retry_backoff 不能为负")

    @property
    def topic(self) -> str:
        """``apns-topic`` 头的默认值（源实现：``topic = self.bundle_id``）。"""
        return self.bundle_id.strip()
