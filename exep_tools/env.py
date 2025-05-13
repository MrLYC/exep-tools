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
        if not os.path.exists(loaded_magic.local_file):
            raise FileNotFoundError(f"File not found: {loaded_magic.local_file}")

        with open(loaded_magic.local_file) as f:
            content = f.read()
        return content, int(datetime.now(UTC).timestamp())

    def get_file(self) -> str:
        loaded_magic = self.loaded_magic
        until_time = loaded_magic.until_ts

        try:
            content, ftime = self.get_local_file()
            need_update = False
        except FileNotFoundError:
            content, ftime = self.get_remote_file()
            need_update = True

        if ftime > until_time:
            raise RuntimeError(f"EXEP is no longer valid, last modified time: {ftime}, expired time: {until_time}")

        elif need_update:
            # get_remote_file 返回的 content 是 str，需要编码为 bytes
            with open(loaded_magic.local_file, "wb") as f:
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
