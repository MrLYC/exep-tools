import base64
import pytest
from exep_tools.crypto import Cipher


class TestCipher:
    def test_init_with_str(self):
        """Test initialization with string key and nonce"""
        key = "0000000000000000"
        nonce = "yakov"
        cipher = Cipher(str_key=key, str_nonce=nonce)

        assert cipher.key == key.encode()
        assert cipher.nonce == nonce.encode()

    def test_init_with_base64(self):
        """Test initialization with base64 key and nonce"""
        key = "dGVzdGtleWZvcnRlc3Rpbmc="  # base64 for "0000000000000000"
        nonce = "dGVzdG5vbmNlZm9ydGVzdA=="  # base64 for "yakov"
        cipher = Cipher(base64_key=key, base64_nonce=nonce)

        assert cipher.key == base64.b64decode(key)
        assert cipher.nonce == base64.b64decode(nonce)

    def test_encrypt_decrypt(self):
        """Test encryption and decryption work correctly"""
        cipher = Cipher(str_key="0000000000000000", str_nonce="yakov")
        original_data = b"Hello, this is a test message!"

        # Test encrypt/decrypt
        encrypted = cipher.encrypt(original_data)
        decrypted = cipher.decrypt(encrypted)

        assert decrypted == original_data
        assert encrypted != original_data  # Ensure encryption actually happened

    def test_encrypt_decrypt_base64(self):
        """Test base64 encryption and decryption work correctly"""
        cipher = Cipher(str_key="0000000000000000", str_nonce="yakov")
        original_data = b"Hello, this is a test message!"

        # Test encrypt_base64/decrypt_base64
        encrypted_b64 = cipher.encrypt_base64(original_data)
        decrypted = cipher.decrypt_base64(encrypted_b64)

        assert decrypted == original_data
        assert encrypted_b64 != original_data  # Ensure encryption actually happened

        # Ensure the output is valid base64
        try:
            base64.b64decode(encrypted_b64)
            is_valid_base64 = True
        except Exception:
            is_valid_base64 = False

        assert is_valid_base64
