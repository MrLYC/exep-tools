import codecs
import json
import logging
import os
from dataclasses import InitVar, dataclass
from datetime import datetime
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


@dataclass
class Loader:
    key: str
    nonce: str
    magic: InitVar[str]
    access_token: str = ""
    base_url: str = ""
    ref_name: str = ""
    until_ts: int = 0
    remote_file: str = ""
    local_file: str = ""

    def __post_init__(self, magic: str) -> None:
        cipher = self.cipher
        decrypted_magic = cipher.decrypt_base64(magic).decode()
        dumped_magic = json.loads(decrypted_magic)
        magic_obj = Magic(**dumped_magic)

        if not self.access_token:
            self.access_token = magic_obj.access_token

        if not self.base_url:
            self.base_url = magic_obj.base_url

        if not self.ref_name:
            self.ref_name = magic_obj.ref_name

        if not self.until_ts:
            self.until_ts = magic_obj.until_ts

        if not self.remote_file:
            self.remote_file = magic_obj.remote_file

        if not self.local_file:
            self.local_file = magic_obj.local_file

    @cached_property
    def cipher(self) -> Cipher:
        return Cipher(base64_key=codecs.decode(self.key, "rot13"), str_nonce=self.nonce)

    def get_remote_file(self) -> tuple[str, datetime]:
        file_path = self.remote_file
        path = file_path.strip("/")
        response = requests.get(
            urljoin(
                self.base_url,
                f"repository/files/{path.replace('/', '%2F')}/raw",
            ),
            headers={"PRIVATE-TOKEN": self.access_token},
            params={"ref": self.ref_name},
            timeout=60,
        )
        response.raise_for_status()

        headers = response.headers
        if headers.get("X-Gitlab-File-Path") != file_path:
            raise RuntimeError("File path does not match")

        date = response.headers.get("Date")
        if not date:
            return response.text, datetime.utcnow()

        return response.text, dateutil_parser.parse(date)

    def get_local_file(self) -> tuple[str, datetime]:
        if not os.path.exists(self.local_file):
            raise FileNotFoundError(f"File not found: {self.local_file}")

        with open(self.local_file) as f:
            content = f.read()
        return content, datetime.utcnow()

    def get_file(self) -> str:
        until_time = datetime.fromtimestamp(self.until_ts)

        try:
            content, mtime = self.get_local_file()
        except FileNotFoundError:
            content, mtime = self.get_remote_file()

            if mtime < until_time:
                # get_remote_file 返回的 content 是 str，需要编码为 bytes
                with open(self.local_file, "wb") as f:
                    f.write(content.encode("utf-8"))

        if mtime > until_time:
            raise RuntimeError(f"EXEP is no longer valid, last modified time: {mtime}, expired time: {until_time}")

        return content

    def load_encrypted_env(self) -> bool:
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
