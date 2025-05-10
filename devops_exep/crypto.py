import base64
from Crypto.Cipher import AES
from dataclasses import dataclass, InitVar, field


@dataclass
class Cipher:
    """AES加密和解密类"""

    str_key: InitVar[str] = ""
    str_nonce: InitVar[str] = ""
    base64_key: InitVar[str] = ""
    base64_nonce: InitVar[str] = ""
    key: bytes = b""
    nonce: bytes = b""

    def __post_init__(
        self, str_key: str, str_nonce: str, base64_key: str, base64_nonce: str
    ):
        if str_key:
            self.key = str_key.encode()
        elif base64_key:
            self.key = base64.b64decode(base64_key)

        if str_nonce:
            self.nonce = str_nonce.encode()
        elif base64_nonce:
            self.nonce = base64.b64decode(base64_nonce)

    @property
    def cipher(self):
        return AES.new(self.key, AES.MODE_CTR, nonce=self.nonce)

    def encrypt(self, data: bytes) -> bytes:
        """使用AES加密数据"""
        return self.cipher.encrypt(data)

    def encrypt_base64(self, data: bytes) -> bytes:
        """使用AES加密数据并返回base64编码"""
        ciphertext = self.encrypt(data)
        return base64.b64encode(ciphertext)

    def decrypt(self, data: bytes) -> bytes:
        """使用AES解密数据"""
        return self.cipher.decrypt(data)

    def decrypt_base64(self, data: str) -> bytes:
        """使用AES解密base64编码的数据"""
        ciphertext = base64.b64decode(data)
        return self.decrypt(ciphertext)
