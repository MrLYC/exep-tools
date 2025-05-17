import codecs
import json
import logging
import os
from dataclasses import InitVar, dataclass, field
from datetime import UTC, datetime
from functools import cached_property
from io import StringIO
from urllib.parse import urljoin

import requests
from dateutil import parser as dateutil_parser
from dotenv import load_dotenv

from exep_tools.crypto import Cipher

logger = logging.getLogger(__name__)


@dataclass
class Magic:
    access_token: str
    base_url: str
    until_ts: int
    ref_name: str = "main"
    remote_file: str = ".ex"
    local_file: str = ".ex"
    allow_commands: list[str] | None = None
    disallow_commands: list[str] | None = None
    environments: dict[str, str] | None = None


@dataclass
class Loader:
    key: str
    name: str
    magic: InitVar[str]
    command: str
    loaded_magic: Magic = field(init=False)

    def __post_init__(self, magic: str) -> None:
        cipher = self.cipher
        decrypted_magic = cipher.decrypt_base64(magic).decode()
        dumped_magic = json.loads(decrypted_magic)
        self.loaded_magic = Magic(**dumped_magic)

    @cached_property
    def cipher(self) -> Cipher:
        return Cipher(base64_key=codecs.decode(self.key, "rot13"), str_nonce=self.name)

    def get_remote_file(self) -> tuple[str, int]:
        loaded_magic = self.loaded_magic
        file_path = loaded_magic.remote_file
        path = file_path.strip("/")
        response = requests.get(
            urljoin(
                loaded_magic.base_url,
                f"repository/files/{path.replace('/', '%2F')}/raw",
            ),
            headers={"PRIVATE-TOKEN": loaded_magic.access_token},
            params={"ref": loaded_magic.ref_name},
            timeout=60,
        )
        response.raise_for_status()

        headers = response.headers
        if headers.get("X-Gitlab-File-Path") != file_path:
            raise RuntimeError("File path does not match")

        date = response.headers.get("Date")
        if not date:
            return response.text, int(datetime.now(UTC).timestamp())

        return response.text, int(dateutil_parser.parse(date).timestamp())

    def get_local_file(self) -> tuple[str, int]:
        loaded_magic = self.loaded_magic
        file_path = loaded_magic.local_file
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path) as f:
            content = f.read()

        # 获取当前机器时间和文件的创建、修改、访问时间中的最大值
        current_time = int(datetime.now(UTC).timestamp())
        stat_info = os.stat(file_path)
        # st_ctime 是文件创建时间（Windows）或最后元数据更改时间（Unix）
        # st_mtime 是文件最后修改时间
        # st_atime 是文件最后访问时间
        file_times = [stat_info.st_ctime, stat_info.st_mtime, stat_info.st_atime]
        max_file_time = max([*file_times, current_time])

        return content, int(max_file_time)

    def get_file(self) -> str:
        loaded_magic = self.loaded_magic
        until_time = loaded_magic.until_ts
        local_file_path = loaded_magic.local_file

        # 检查本地文件是否存在
        if os.path.exists(local_file_path):
            try:
                # 尝试读取本地文件
                content, ftime = self.get_local_file()
                # 如果本地文件过期，删除然后按远程文件处理
                if ftime >= until_time:
                    os.remove(local_file_path)
                    # 按第一种情况（远程文件）处理
                    return self._get_and_save_remote_file(until_time)
                else:
                    # 本地文件有效，直接返回内容
                    return content
            except FileNotFoundError:
                # 如果读取过程中文件被删除，按远程文件处理
                return self._get_and_save_remote_file(until_time)
        # 本地文件不存在，按远程文件处理
        return self._get_and_save_remote_file(until_time)

    def _get_and_save_remote_file(self, until_time: int) -> str:
        """获取远程文件并保存到本地"""
        content, ftime = self.get_remote_file()
        # 检查远程文件是否过期
        if ftime >= until_time:
            raise RuntimeError(f"EXEP is no longer valid, last modified time: {ftime}, expired time: {until_time}")

        # 保存远程文件到本地
        with open(self.loaded_magic.local_file, "wb") as f:
            f.write(content.encode())

        return content

    def check_magic(self):
        loaded_magic = self.loaded_magic

        if loaded_magic.allow_commands is not None and self.command not in loaded_magic.allow_commands:
            raise RuntimeError(f"Command {self.command} is not allowed")

        if loaded_magic.disallow_commands is not None and self.command in loaded_magic.disallow_commands:
            raise RuntimeError(f"Command {self.command} is disallowed")

        if loaded_magic.environments is not None:
            for key, value in loaded_magic.environments.items():
                env = os.getenv(key)
                if env != value:
                    raise RuntimeError(f"Environment variable {key} does not match, expected: {value}, got: {env}")

    def load_encrypted_env(self) -> bool:
        self.check_magic()

        cipher = self.cipher
        content = self.get_file()

        if not content:
            logger.debug("Content is empty")
            return False

        self.load_env(cipher.decrypt_base64(content).decode())
        logger.debug(
            "Decrypted message size: %s, key size: %s, nonce size: %s",
            len(content),
            len(cipher.key),
            len(cipher.nonce),
        )

        return True

    def load_env(self, content: str) -> None:
        load_dotenv(stream=StringIO(content))
