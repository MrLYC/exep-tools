from dataclasses import dataclass, InitVar
import requests
from urllib.parse import urljoin
from dateutil import parser as dateutil_parser
from datetime import datetime
from io import StringIO
from exep_tools.crypto import Cipher
import codecs
import logging
import os
import json
from dotenv import load_dotenv
import click
from functools import cached_property

logger = logging.getLogger(__name__)


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

    def __post_init__(self, magic: str):
        cipher = self.cipher
        decrypted_magic = cipher.decrypt_base64(magic).decode()
        dumped_magic = json.loads(decrypted_magic)

        if not self.access_token:
            self.access_token = dumped_magic["access_token"]

        if not self.base_url:
            self.base_url = dumped_magic["base_url"]

        if not self.ref_name:
            self.ref_name = dumped_magic.get("ref_name", "main")

        if not self.until_ts:
            self.until_ts = dumped_magic["until_ts"]

        if not self.remote_file:
            self.remote_file = dumped_magic.get("remote_file", ".ex")

        if not self.local_file:
            self.local_file = dumped_magic.get("local_file", ".ex")

    @cached_property
    def cipher(self):
        return Cipher(base64_key=codecs.decode(self.key, "rot13"), str_nonce=self.nonce)

    def get_remote_file(self) -> (str, datetime):
        file_path = self.remote_file
        path = file_path.strip("/")
        response = requests.get(
            urljoin(
                self.base_url,
                f"repository/files/{path.replace('/', '%2F')}/raw",
            ),
            headers={"PRIVATE-TOKEN": self.access_token},
            params={"ref": self.ref_name},
        )
        response.raise_for_status()

        headers = response.headers
        if headers.get("X-Gitlab-File-Path") != file_path:
            raise RuntimeError("File path does not match")

        date = response.headers.get("Date")
        if not date:
            return response.text, datetime.utcnow()

        return response.text, dateutil_parser.parse(date)

    def get_local_file(self) -> (str, datetime):
        if not os.path.exists(self.local_file):
            raise FileNotFoundError(f"File not found: {self.local_file}")

        with open(self.local_file, "rt") as f:
            content = f.read()
        return content, datetime.fromtimestamp(os.path.getmtime(self.local_file))

    def get_file(self) -> str:
        until_time = datetime.fromtimestamp(self.until_ts)

        try:
            content, mtime = self.get_local_file()
        except FileNotFoundError:
            content, mtime = self.get_remote_file()

            if mtime < until_time:
                with open(self.local_file, "wb") as f:
                    f.write(content)

        if mtime > until_time:
            raise RuntimeError(
                f"EXEP is no longer valid, last modified time: {mtime}, expired time: {until_time}"
            )

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

    def load_env(self, content: str):
        load_dotenv(stream=StringIO(content))
