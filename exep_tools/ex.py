import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Optional

import requests
from dateutil import parser as dateutil_parser

from exep_tools.crypto import Cipher

logger = logging.getLogger(__name__)


@dataclass
class EX:
    """
    EX 是一种加密的 JSON 格式，包含 meta 和 payload 两个结构。
    meta 是固定结构，目前只有 expire 时间戳。
    payload 是动态结构，取决于具体使用场景。
    """

    meta: dict[str, Any]
    payload: dict[str, Any]

    @property
    def expire(self) -> int:
        """获取过期时间戳"""
        return self.meta.get("expire", 0)

    @staticmethod
    def from_json(json_data: str) -> "EX":
        """从 JSON 字符串创建 EX 对象"""
        data = json.loads(json_data)
        return EX(meta=data.get("meta", {}), payload=data.get("payload", {}))

    def to_json(self) -> str:
        """转换为 JSON 字符串"""
        return json.dumps({"meta": self.meta, "payload": self.payload})

    def is_expired(self, timestamp: int) -> bool:
        """
        检查 EX 是否已过期

        Args:
            timestamp: 用于比较的时间戳

        Returns:
            bool: 如果 timestamp >= expire，表示已过期，返回 True；否则返回 False
        """
        return timestamp >= self.expire


@dataclass
class EXEP:
    """
    EXEP 是 EX 的一种扩展协议，主要是对 payload 的结构进行固化。
    通过 EXEP 可以配置获取 EX 的远程请求参数。
    """

    meta: dict[str, Any]
    payload: dict[str, Any]

    @property
    def url(self) -> str:
        """获取请求 URL"""
        return self.payload.get("url", "")

    @property
    def request_headers(self) -> dict[str, str]:
        """获取请求头"""
        return self.payload.get("request_headers", {})

    @property
    def queries(self) -> dict[str, str]:
        """获取查询参数"""
        return self.payload.get("queries", {})

    @property
    def response_headers(self) -> list[str]:
        """获取需要验证的响应头名称列表"""
        return self.payload.get("response_headers", [])

    @property
    def expire(self) -> int:
        """获取过期时间戳"""
        return self.meta.get("expire", 0)

    @staticmethod
    def from_json(json_data: str) -> "EXEP":
        """从 JSON 字符串创建 EXEP 对象"""
        data = json.loads(json_data)
        return EXEP(meta=data.get("meta", {}), payload=data.get("payload", {}))


class EXLoader:
    """
    EX 加载器，负责处理 EX 的加载、验证和缓存。
    支持通过 EXEP 远程拉取和从本地文件加载两种方式。
    """

    def __init__(self, cipher: Cipher):
        """
        初始化 EX 加载器

        Args:
            cipher: 用于加解密的 Cipher 对象
        """
        self.cipher = cipher
        self._ex_search_paths = [
            os.path.join(os.getcwd(), ".ex"),  # 工作目录
            os.path.join(os.path.expanduser("~"), ".ex"),  # home 目录
        ]

    def load_from_exep(self, exep_content: str) -> EX:
        """
        通过 EXEP 加载 EX

        Args:
            exep_content: 加密的 EXEP 内容

        Returns:
            EX: 解密并验证后的 EX 对象

        Raises:
            RuntimeError: 如果 EXEP 验证失败、请求失败或 EX 已过期
        """
        # 解密 EXEP
        decrypted_exep = self.cipher.decrypt_base64(exep_content).decode()
        exep = EXEP.from_json(decrypted_exep)

        # 检查 EXEP 是否过期
        current_time = int(datetime.now(UTC).timestamp())
        if exep.expire <= current_time:
            raise RuntimeError(f"EXEP 已过期: {exep.expire} <= {current_time}")

        # 获取并验证 EX
        ex_content, response_date = self._fetch_ex_from_exep(exep)

        # 解密 EX 内容
        decrypted_ex = self.cipher.decrypt_base64(ex_content).decode()
        ex = EX.from_json(decrypted_ex)

        # 检查 EX 是否过期
        response_timestamp = int(dateutil_parser.parse(response_date).timestamp())
        if ex.is_expired(response_timestamp):
            raise RuntimeError(f"EX 已过期: {ex.expire} <= {response_timestamp}")

        # 缓存到本地
        self._save_to_local(ex_content)

        return ex

    def _fetch_ex_from_exep(self, exep: EXEP) -> tuple[str, str]:
        """
        根据 EXEP 配置请求 EX

        Args:
            exep: EXEP 对象

        Returns:
            Tuple[str, str]: 包含 EX 内容和响应的 Date 头

        Raises:
            RuntimeError: 如果请求失败或响应头验证失败
        """
        try:
            response = requests.get(exep.url, headers=exep.request_headers, params=exep.queries, timeout=30)
            response.raise_for_status()

            # 验证响应头
            for header_name in exep.response_headers:
                if header_name not in response.headers:
                    raise RuntimeError(f"响应头缺少必需的字段: {header_name}")

            # 确保有 Date 头用于后续验证
            if "Date" not in response.headers:
                raise RuntimeError("响应头缺少 Date 字段")

            return response.text, response.headers["Date"]

        except requests.RequestException as e:
            raise RuntimeError(f"请求 EX 失败: {e}") from e

    def load_from_local(self) -> Optional[EX]:
        """
        从本地加载 EX

        Returns:
            Optional[EX]: 如果找到有效的 EX 文件则返回 EX 对象，否则返回 None
        """
        for path in self._ex_search_paths:
            if os.path.exists(path):
                try:
                    # 获取文件时间戳
                    timestamp = self._get_file_timestamp(path)

                    # 读取文件内容
                    with open(path) as f:
                        encrypted_content = f.read()

                    # 解密内容
                    decrypted_content = self.cipher.decrypt_base64(encrypted_content).decode()
                    ex = EX.from_json(decrypted_content)

                    # 检查是否过期
                    if ex.is_expired(timestamp):
                        logger.info(f"本地 EX 文件已过期: {path}")
                        os.remove(path)  # 删除过期文件
                        continue

                    logger.info(f"从本地加载 EX: {path}")
                    return ex

                except Exception:
                    logger.exception(f"加载本地 EX 文件失败: {path}")
                    continue

        return None

    def _get_file_timestamp(self, file_path: str) -> int:
        """
        获取文件的时间戳，取当前时间和文件的创建、修改、访问时间的最大值

        Args:
            file_path: 文件路径

        Returns:
            int: 时间戳
        """
        current_time = int(time.time())
        stat_info = os.stat(file_path)
        file_times = [
            stat_info.st_ctime,  # 创建时间（Windows）或最后元数据更改时间（Unix）
            stat_info.st_mtime,  # 最后修改时间
            stat_info.st_atime,  # 最后访问时间
        ]
        return max(int(max(file_times)), current_time)

    def _save_to_local(self, encrypted_content: str) -> None:
        """
        将加密的 EX 内容保存到本地

        Args:
            encrypted_content: 加密的 EX 内容
        """
        # 优先保存到工作目录
        save_path = self._ex_search_paths[0]
        try:
            with open(save_path, "w") as f:
                f.write(encrypted_content)
            logger.info(f"已缓存 EX 到本地: {save_path}")
        except Exception:
            logger.exception(f"保存 EX 到本地失败: {save_path}")

    def load(self, exep_content: Optional[str] = None) -> EX:
        """
        加载 EX，优先从本地加载，如果本地没有或已过期则使用 EXEP 远程加载

        Args:
            exep_content: 可选，加密的 EXEP 内容，用于远程加载

        Returns:
            EX: 加载的 EX 对象

        Raises:
            RuntimeError: 如果无法加载 EX
        """
        # 尝试从本地加载
        ex = self.load_from_local()
        if ex:
            return ex

        # 本地没有或已过期，尝试通过 EXEP 远程加载
        if exep_content:
            return self.load_from_exep(exep_content)

        raise RuntimeError("无法加载 EX: 本地 EX 不可用且未提供 EXEP")
