import os
import json
import codecs
import base64
import pytest
from unittest.mock import patch, MagicMock, mock_open
from datetime import datetime, timedelta
from io import StringIO

import requests
import requests_mock
from devops_exep.env import Loader
from devops_exep.crypto import Cipher


@pytest.fixture
def key():
    """Create a sample key"""
    return "0" * 32


@pytest.fixture
def nonce():
    """Create a sample nonce"""
    return "yakov"


@pytest.fixture
def loader_key(key):
    """Create a sample key"""
    return codecs.encode(base64.b64encode(key.encode()).decode(), "rot13")


@pytest.fixture
def magic():
    """Create a sample magic string"""
    # This would normally be encrypted, but for testing we can use a simple string
    return {
        "access_token": "fake_token",
        "base_url": "https://fake-gitlab.com/api/v4/projects/123/",
        "ref_name": "main",
        "until_ts": int((datetime.now() + timedelta(days=1)).timestamp()),
        "remote_file": "test-remote.ex",
        "local_file": "test-local.ex",
    }


@pytest.fixture
def encrypted_magic(magic, key, nonce):
    """Create a sample encrypted magic string"""
    # Encrypt the magic string using the Cipher
    cipher = Cipher(str_key=key, str_nonce=nonce)
    dumped_magic = json.dumps(magic).encode()
    encrypted_magic = cipher.encrypt_base64(dumped_magic).decode()
    return encrypted_magic


@pytest.fixture
def cipher(key, nonce):
    """Create a sample Cipher instance"""
    return Cipher(str_key=key, str_nonce=nonce)


@pytest.fixture
def loader(loader_key, nonce, encrypted_magic, cipher):
    """Create a sample Loader instance"""
    return Loader(key=loader_key, nonce=nonce, magic=encrypted_magic)


@pytest.fixture
def decrypted_ex(cipher):
    return "KEY1=value"


@pytest.fixture
def encrypted_ex(decrypted_ex, cipher):
    return cipher.encrypt_base64(decrypted_ex.encode()).decode()


@pytest.fixture
def magic_env(encrypted_magic):
    key = "mock_magic_value"
    os.environ[key] = encrypted_magic

    yield key

    del os.environ[key]


class TestLoader:
    def test_init(self, loader):
        """Test Loader initialization with magic string"""
        # 因为我们使用的是 fixture 创建的 loader 实例，所以不需要再创建一个新的
        # 可以直接断言 loader 实例的属性是否正确初始化

        # Assert that the Loader correctly initializes from the magic string
        assert loader.access_token == "fake_token"
        assert loader.base_url == "https://fake-gitlab.com/api/v4/projects/123/"
        assert loader.ref_name == "main"
        assert loader.remote_file == "test-remote.ex"
        assert loader.local_file == "test-local.ex"
        assert isinstance(loader.until_ts, int)  # 检查时间戳是否正确初始化为整数

    def test_get_remote_file(self, requests_mock, loader):
        """Test getting a remote file"""
        # Mock the GitLab API response
        requests_mock.get(
            "https://fake-gitlab.com/api/v4/projects/123/repository/files/test-remote.ex/raw?ref=main",
            text="encrypted_content",
            headers={
                "X-Gitlab-File-Path": "test-remote.ex",
                "Date": "Mon, 10 May 2025 12:00:00 GMT",
            },
        )

        content, date = loader.get_remote_file()

        assert content == "encrypted_content"
        assert date.day == 10
        assert date.month == 5
        assert date.year == 2025

    def test_get_remote_file_path_mismatch(self, requests_mock, loader):
        """Test error when file path doesn't match"""
        # Mock the GitLab API response with wrong path
        requests_mock.get(
            "https://fake-gitlab.com/api/v4/projects/123/repository/files/test-remote.ex/raw?ref=main",
            text="encrypted_content",
            headers={
                "X-Gitlab-File-Path": "wrong-path.ex",
                "Date": "Mon, 10 May 2025 12:00:00 GMT",
            },
        )

        with pytest.raises(RuntimeError, match="File path does not match"):
            loader.get_remote_file()

    def test_get_local_file(self, loader):
        """Test getting a local file"""
        mock_content = "local encrypted content"
        mock_time = 1746858062  # 2025-05-10 in epoch time

        with patch("os.path.exists", return_value=True), patch(
            "builtins.open", mock_open(read_data=mock_content)
        ), patch("os.path.getmtime", return_value=mock_time):

            content, date = loader.get_local_file()

            assert content == mock_content
            assert date == datetime.fromtimestamp(mock_time)
            # 更详细的日期检查
            assert date.day == 10
            assert date.month == 5
            assert date.year == 2025

    def test_get_local_file_not_found(self, loader):
        """Test error when local file doesn't exist"""
        with patch("os.path.exists", return_value=False):
            # 设置 local_file 为不存在的文件
            loader.local_file = "nonexistent.ex"

            with pytest.raises(FileNotFoundError):
                loader.get_local_file()

    def test_get_file_uses_local_if_exists(self, loader):
        """Test that get_file uses local file if it exists and isn't expired"""
        mock_local_content = "local content"
        mock_time = datetime.now().timestamp()

        # Mock the get_local_file method to return our test content
        with patch.object(
            loader,
            "get_local_file",
            return_value=(mock_local_content, datetime.fromtimestamp(mock_time)),
        ), patch.object(loader, "get_remote_file") as mock_get_remote:

            content = loader.get_file()

            assert content == mock_local_content
            # Make sure we didn't call get_remote_file
            mock_get_remote.assert_not_called()

    def test_get_file_uses_remote_if_local_missing(self, requests_mock, loader):
        """Test that get_file uses remote file if local is missing"""
        mock_remote_content = "remote content"

        # 修改 local_file 为不存在的文件
        loader.local_file = "nonexistent.ex"

        # Mock get_local_file to raise FileNotFoundError
        with patch.object(
            loader, "get_local_file", side_effect=FileNotFoundError
        ), patch.object(
            loader,
            "get_remote_file",
            return_value=(mock_remote_content, datetime.now()),
        ), patch(
            "builtins.open", mock_open()
        ) as mock_file:

            content = loader.get_file()

            assert content == mock_remote_content
            # Verify we attempted to write the remote content to local file
            mock_file.assert_called_once_with("nonexistent.ex", "wb")

    def test_get_file_expired(self, loader):
        """Test that get_file raises error if file is expired"""
        mock_local_content = "local content"
        past_time = (datetime.now() - timedelta(days=1)).timestamp()

        # 设置过期时间
        loader.until_ts = int(past_time)  # 过期时间戳

        # Mock the get_local_file method to return our test content with current time
        with patch.object(
            loader, "get_local_file", return_value=(mock_local_content, datetime.now())
        ):
            with pytest.raises(RuntimeError, match="EXEP is no longer valid"):
                loader.get_file()

    def test_load_encrypted_env(self, loader, cipher, decrypted_ex, encrypted_ex):
        """Test loading encrypted env variables"""
        with patch.object(loader, "get_file", return_value=encrypted_ex), patch.object(
            loader, "load_env"
        ) as mock_load_env:
            assert loader.load_encrypted_env()
            mock_load_env.assert_called_once_with(decrypted_ex)
