import base64
import codecs
from dataclasses import InitVar, dataclass
from hashlib import sha256
from typing import Any

from Crypto.Cipher import AES


@dataclass
class Cipher:
    """AES加密和解密类"""

    str_key: InitVar[str] = ""
    str_nonce: InitVar[str] = ""
    base64_key: InitVar[str] = ""
    base64_nonce: InitVar[str] = ""
    rot13_key: InitVar[str] = ""
    key: bytes = b""
    nonce: bytes = b""

    def __post_init__(self, str_key: str, str_nonce: str, base64_key: str, base64_nonce: str, rot13_key: str) -> None:
        if str_key:
            self.key = str_key.encode()
        elif base64_key:
            self.key = base64.b64decode(base64_key)
        elif rot13_key:
            self.key = base64.b64decode(codecs.decode(rot13_key, "rot_13"))

        if str_nonce:
            self.nonce = str_nonce.encode()
        elif base64_nonce:
            self.nonce = base64.b64decode(base64_nonce)

    @property
    def cipher(self) -> Any:
        # mypy 无法识别 pycryptodome 的 AES 类型，使用 Any
        return AES.new(self.key, AES.MODE_CTR, nonce=self.nonce)

    def encrypt(self, data: bytes) -> bytes:
        """使用AES加密数据"""
        return self.cipher.encrypt(data)  # type: ignore[attr-defined]

    def encrypt_base64(self, data: bytes) -> bytes:
        """使用AES加密数据并返回base64编码"""
        ciphertext = self.encrypt(data)
        return base64.b64encode(ciphertext)

    def decrypt(self, data: bytes) -> bytes:
        """使用AES解密数据"""
        return self.cipher.decrypt(data)  # type: ignore[attr-defined]

    def decrypt_base64(self, data: str) -> bytes:
        """使用AES解密base64编码的数据"""
        ciphertext = base64.b64decode(data)
        return self.decrypt(ciphertext)


def generate_nonce(name: str, base: str) -> str:
    """生成nonce"""
    return sha256(f"{name}{base}".encode()).hexdigest()[:10]
