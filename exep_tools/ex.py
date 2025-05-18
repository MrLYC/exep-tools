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
class EXEP(EX):
    """
    EXEP 是 EX 的一种扩展协议，主要是对 payload 的结构进行固化。
    通过 EXEP 可以配置获取 EX 的远程请求参数。
    """

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
    def name(self) -> str:
        """获取名称"""
        return self.meta.get("name", "")

    @property
    def filename(self) -> str:
        """获取文件名，由名称+.ex组成"""
        return f"{self.name}.ex"

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
        self._filename = ".ex"  # 默认文件名

    def _get_search_paths(self, filename: Optional[str] = None) -> list[str]:
        """
        获取 EX 文件的搜索路径列表

        Args:
            filename: 可选，EX 文件名，默认为 .ex

        Returns:
            list[str]: 搜索路径列表
        """
        filename = filename or self._filename
        return [
            os.path.join(os.getcwd(), filename),  # 工作目录
            os.path.join(os.path.expanduser("~"), filename),  # home 目录
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
        encrypted_content, response_date = self._fetch_ex_from_exep(exep)

        # 解密 EX 内容
        ex = decrypt_ex(encrypted_content, self.cipher)

        # 检查 EX 是否过期
        response_timestamp = int(dateutil_parser.parse(response_date).timestamp())
        if ex.is_expired(response_timestamp):
            raise RuntimeError(f"EX 已过期: {ex.expire} <= {response_timestamp}")

        # 获取文件名并缓存到本地
        filename = exep.filename if exep.name else self._filename
        self._save_to_local(encrypted_content, filename)

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

    def load_from_local(self, filename: Optional[str] = None) -> Optional[EX]:
        """
        从本地加载 EX

        Args:
            filename: 可选，要加载的文件名，默认为 self._filename

        Returns:
            Optional[EX]: 如果找到有效的 EX 文件则返回 EX 对象，否则返回 None
        """
        search_paths = self._get_search_paths(filename)
        for path in search_paths:
            if os.path.exists(path):
                try:
                    # 获取文件时间戳
                    timestamp = self._get_file_timestamp(path)

                    # 读取文件内容
                    with open(path) as f:
                        encrypted_content = f.read()

                    # 解密内容
                    ex = decrypt_ex(encrypted_content, self.cipher)

                    # 检查是否过期
                    if ex.is_expired(timestamp):
                        logger.info("本地 EX 文件已过期: %s", path)
                        os.remove(path)  # 删除过期文件
                        continue

                    logger.info("从本地加载 EX: %s", path)
                    return ex

                except Exception:
                    logger.exception("加载本地 EX 文件失败: %s", path)
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

    def save_ex_to_local(self, ex: EX, filename: Optional[str] = None) -> None:
        """
        将 EX 对象保存到本地

        Args:
            ex: 需要保存的 EX 对象
            filename: 可选，保存的文件名，默认为 self._filename
        """
        encrypted_content = excrypt_ex(ex, self.cipher)
        self._save_to_local(encrypted_content, filename)

    def _save_to_local(self, encrypted_content: str, filename: Optional[str] = None) -> None:
        """
        将加密的 EX 内容保存到本地
        首先保存到第一个搜索路径，然后为其余路径创建符号链接

        Args:
            encrypted_content: 加密的 EX 内容字符串
            filename: 可选，保存的文件名，默认为 self._filename
        """
        # 获取搜索路径
        search_paths = self._get_search_paths(filename)

        # 优先保存到工作目录（第一个搜索路径）
        primary_path = search_paths[0]
        # 确保目标目录存在
        os.makedirs(os.path.dirname(primary_path), exist_ok=True)

        # 写入内容到主文件
        with open(primary_path, "w") as f:
            f.write(encrypted_content)
        logger.info("已缓存 EX 到本地: %s", primary_path)

        # 为其余搜索路径创建符号链接
        for link_path in search_paths[1:]:
            try:
                # 如果已存在，先删除旧文件或链接
                if os.path.exists(link_path):
                    if os.path.islink(link_path):
                        os.unlink(link_path)
                    else:
                        os.remove(link_path)

                # 确保目标目录存在
                os.makedirs(os.path.dirname(link_path), exist_ok=True)

                # 创建符号链接
                os.symlink(primary_path, link_path)
                logger.info("已创建符号链接: %s -> %s", link_path, primary_path)
            except Exception:
                logger.exception("创建符号链接失败: %s -> %s", link_path, primary_path)

    def load(self, exep_content: Optional[str] = None, filename: Optional[str] = None) -> EX:
        """
        加载 EX，优先从本地加载，如果本地没有或已过期则使用 EXEP 远程加载

        Args:
            exep_content: 可选，加密的 EXEP 内容，用于远程加载
            filename: 可选，要加载的文件名，默认为 self._filename

        Returns:
            EX: 加载的 EX 对象

        Raises:
            RuntimeError: 如果无法加载 EX
        """
        # 尝试从本地加载
        ex = self.load_from_local(filename)
        if ex:
            return ex

        # 本地没有或已过期，尝试通过 EXEP 远程加载
        if exep_content:
            return self.load_from_exep(exep_content)

        raise RuntimeError("无法加载 EX: 本地 EX 不可用且未提供 EXEP")


def excrypt_ex(ex: EX, cipher: Cipher) -> str:
    """
    将 EX 对象加密为字符串

    Args:
        ex: EX 对象
        cipher: 用于加密的 Cipher 对象

    Returns:
        str: 加密后的 EX 字符串
    """
    ex_json = ex.to_json()
    encrypted_ex = cipher.encrypt_base64(ex_json.encode()).decode()
    return encrypted_ex


def decrypt_ex(encrypted_ex: str, cipher: Cipher) -> EX:
    """
    解密字符串为 EX 对象

    Args:
        encrypted_ex: 加密的 EX 字符串
        cipher: 用于解密的 Cipher 对象

    Returns:
        EX: 解密后的 EX 对象
    """
    decrypted_ex = cipher.decrypt_base64(encrypted_ex.encode()).decode()
    return EX.from_json(decrypted_ex)
