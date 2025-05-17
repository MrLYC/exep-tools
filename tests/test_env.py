import base64
import codecs
import json
import os
from datetime import UTC, datetime, timedelta
from unittest.mock import mock_open, patch

import pytest

from exep_tools.crypto import Cipher
from exep_tools.env import Loader


@pytest.fixture
def key():
    """Create a sample key"""
    return "0" * 32


@pytest.fixture
def name():
    """Create a sample name"""
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
        "until_ts": int((datetime.now(UTC) + timedelta(days=1)).timestamp()),
        "remote_file": "test-remote.ex",
        "local_file": "test-local.ex",
        "allow_commands": None,
    }


@pytest.fixture
def encrypted_magic(magic, key, name):
    """Create a sample encrypted magic string"""
    # Encrypt the magic string using the Cipher
    cipher = Cipher(str_key=key, str_nonce=name)
    dumped_magic = json.dumps(magic).encode()
    encrypted_magic = cipher.encrypt_base64(dumped_magic).decode()
    return encrypted_magic


@pytest.fixture
def cipher(key, name):
    """Create a sample Cipher instance"""
    return Cipher(str_key=key, str_nonce=name)


@pytest.fixture
def command():
    """Create a sample command"""
    return "test_command"


@pytest.fixture
def loader(loader_key, name, encrypted_magic, cipher, command):
    """Create a sample Loader instance"""
    return Loader(key=loader_key, name=name, command=command, magic=encrypted_magic)


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
    @pytest.mark.parametrize(
        "allow,cmd,should_raise",
        [(["a"], "b", True), (["a", "b"], "b", False), (None, "b", False)],
    )
    def test_check_magic_allow_commands(self, loader, allow, cmd, should_raise):
        loader.loaded_magic.allow_commands = allow
        loader.command = cmd
        if should_raise:
            with pytest.raises(RuntimeError, match="not allowed"):
                loader.check_magic()
        else:
            loader.check_magic()

    @pytest.mark.parametrize(
        "disallow,cmd,should_raise",
        [(["a"], "a", True), (["a"], "b", False), (None, "b", False)],
    )
    def test_check_magic_disallow_commands(self, loader, disallow, cmd, should_raise):
        loader.loaded_magic.disallow_commands = disallow
        loader.command = cmd
        if should_raise:
            with pytest.raises(RuntimeError, match="disallowed"):
                loader.check_magic()
        else:
            loader.check_magic()

    def test_check_magic_environments(self, loader, monkeypatch):
        loader.loaded_magic.environments = {"FOO": "BAR"}
        monkeypatch.setenv("FOO", "BAR")
        loader.check_magic()  # 不抛异常
        monkeypatch.setenv("FOO", "BAZ")
        with pytest.raises(RuntimeError, match="does not match"):
            loader.check_magic()

    def test_load_encrypted_env_check_magic_fail(self, loader):
        # check_magic 抛异常
        with patch.object(loader, "check_magic", side_effect=RuntimeError("fail")):
            with pytest.raises(RuntimeError, match="fail"):
                loader.load_encrypted_env()

    def test_load_encrypted_env_empty_content(self, loader):
        # get_file 返回空内容
        with patch.object(loader, "get_file", return_value=""):
            assert loader.load_encrypted_env() is False

    def test_load_encrypted_env_decrypt_fail(self, loader, encrypted_ex):
        # 解密失败
        with (
            patch.object(loader, "get_file", return_value=encrypted_ex),
            patch.object(loader, "cipher") as mock_cipher,
        ):
            mock_cipher.decrypt_base64.side_effect = Exception("decrypt error")
            with pytest.raises(Exception, match="decrypt error"):
                loader.load_encrypted_env()

    def test_load_env_sets_env(self, loader, monkeypatch):
        # load_env 能正确设置环境变量
        content = "FOO=BAR\nBAR=BAZ"
        for k in ["FOO", "BAR"]:
            if k in os.environ:
                monkeypatch.delenv(k, raising=False)
        loader.load_env(content)
        assert os.environ["FOO"] == "BAR"
        assert os.environ["BAR"] == "BAZ"

    def test_init(self, loader):
        """Test Loader initialization with magic string"""
        # 因为我们使用的是 fixture 创建的 loader 实例，所以不需要再创建一个新的
        # 可以直接断言 loader 实例的属性是否正确初始化

        # Assert that the Loader correctly initializes from the magic string
        loaded_magic = loader.loaded_magic
        assert loaded_magic.access_token == "fake_token"
        assert loaded_magic.base_url == "https://fake-gitlab.com/api/v4/projects/123/"
        assert loaded_magic.ref_name == "main"
        assert loaded_magic.remote_file == "test-remote.ex"
        assert loaded_magic.local_file == "test-local.ex"
        assert isinstance(loaded_magic.until_ts, int)  # 检查时间戳是否正确初始化为整数

    def test_get_remote_file(self, requests_mock, loader):
        """Test getting a remote file"""
        # Mock the GitLab API response
        now = datetime.now(UTC)
        requests_mock.get(
            "https://fake-gitlab.com/api/v4/projects/123/repository/files/test-remote.ex/raw?ref=main",
            text="encrypted_content",
            headers={
                "X-Gitlab-File-Path": "test-remote.ex",
                "Date": f"{now.isoformat()}",
            },  # Mock the Date header
        )

        content, time = loader.get_remote_file()

        assert content == "encrypted_content"
        assert time == int(now.timestamp())

    def test_get_remote_file_path_mismatch(self, requests_mock, loader):
        """Test error when file path doesn't match"""
        now = datetime.now(UTC)
        # Mock the GitLab API response with wrong path
        requests_mock.get(
            "https://fake-gitlab.com/api/v4/projects/123/repository/files/test-remote.ex/raw?ref=main",
            text="encrypted_content",
            headers={
                "X-Gitlab-File-Path": "wrong-path.ex",
                "Date": f"{now.isoformat()}",
            },
        )

        with pytest.raises(RuntimeError, match="File path does not match"):
            loader.get_remote_file()

    def test_get_local_file(self, loader, tmp_path):
        """Test getting a local file (真实文件，不用 mock)"""

        # 切换到临时目录
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        now = datetime.now(UTC)
        try:
            # 生成本地文件
            local_file = tmp_path / "test_local_file.txt"
            mock_content = "local encrypted content"
            with open(local_file, "w", encoding="utf-8") as f:
                f.write(mock_content)
            # 设置 loader 的 local_file 路径
            loader.loaded_magic.local_file = str(local_file)
            # 调用真实方法
            content, time = loader.get_local_file()
            assert content == mock_content
            assert time >= int(now.timestamp())
        finally:
            os.chdir(old_cwd)

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
        # 设置未来的过期时间
        future_time = int((datetime.now(UTC) + timedelta(days=1)).timestamp())
        loader.loaded_magic.until_ts = future_time

        # 使用当前时间（小于过期时间）
        current_time = int(datetime.now(UTC).timestamp())

        # Mock the get_local_file method to return our test content and current time
        with (
            patch.object(loader, "get_local_file", return_value=(mock_local_content, current_time)),
            patch.object(loader, "get_remote_file") as mock_get_remote,
            patch("os.path.exists", return_value=True),
        ):
            content = loader.get_file()

            assert content == mock_local_content
            # Make sure we didn't call get_remote_file
            mock_get_remote.assert_not_called()

    def test_get_file_uses_remote_if_local_missing(self, loader, tmp_path):
        """Test that get_file uses remote file if local is missing"""
        # 切换到临时目录
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            mock_remote_content = "remote content"
            # 设置 loader 的 loaded_magic.local_file 路径为临时目录下的文件
            local_file = tmp_path / "test_remote_write.txt"
            loader.loaded_magic.local_file = str(local_file)

            # 确保本地文件不存在
            if local_file.exists():
                local_file.unlink()

            # 设置未来的过期时间
            future_time = int((datetime.now(UTC) + timedelta(days=1)).timestamp())
            loader.loaded_magic.until_ts = future_time

            # mock get_remote_file 返回内容和当前时间（小于过期时间）
            now = int(datetime.now(UTC).timestamp())

            with (
                patch.object(loader, "get_remote_file", return_value=(mock_remote_content, now)),
                patch("os.path.exists", return_value=False),  # 确保认为本地文件不存在
            ):
                # 调用 get_file，应该调用远程并写入本地
                content = loader.get_file()
                assert content == mock_remote_content
        finally:
            os.chdir(old_cwd)

    def test_get_file_expired(self, loader, tmp_path):
        """Test that get_file handles expired local file by deleting it and trying remote file"""
        # 切换到临时目录
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            # 准备本地文件
            mock_local_content = "local content"
            mock_remote_content = "remote content"
            local_file = tmp_path / "test_expired.txt"
            with open(local_file, "w", encoding="utf-8") as f:
                f.write(mock_local_content)

            # 设置 loader 的 loaded_magic.local_file 路径
            loader.loaded_magic.local_file = str(local_file)

            # 设置过期时间为过去的时间（比文件时间早）
            past_time = int((datetime.now(UTC) - timedelta(days=1)).timestamp())
            loader.loaded_magic.until_ts = past_time

            # 模拟本地文件返回的时间大于等于过期时间
            # 这会导致本地文件被删除，然后尝试获取远程文件
            future_time = int((datetime.now(UTC) + timedelta(days=2)).timestamp())

            with (
                patch.object(loader, "get_local_file", return_value=(mock_local_content, future_time)),
                patch.object(loader, "get_remote_file") as mock_get_remote,
                patch("os.remove") as mock_remove,  # 模拟文件删除
            ):
                # 配置 get_remote_file 模拟返回内容和过期的时间
                mock_get_remote.return_value = (mock_remote_content, future_time)

                # 调用 get_file 应该报错，因为远程文件也过期了
                with pytest.raises(RuntimeError, match="EXEP is no longer valid"):
                    loader.get_file()

                # 验证删除了本地文件
                mock_remove.assert_called_once_with(str(local_file))
                # 验证尝试了获取远程文件
                mock_get_remote.assert_called_once()
        finally:
            os.chdir(old_cwd)

    def test_get_file_local_expired_remote_valid(self, loader, tmp_path):
        """Test that get_file deletes expired local file and fetches valid remote file"""
        # 切换到临时目录
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            # 准备本地文件
            mock_local_content = "local content"
            mock_remote_content = "remote content"
            local_file = tmp_path / "test_expired_remote_valid.txt"
            with open(local_file, "w", encoding="utf-8") as f:
                f.write(mock_local_content)

            # 设置 loader 的 loaded_magic.local_file 路径
            loader.loaded_magic.local_file = str(local_file)

            # 设置未来的过期时间
            future_time = int((datetime.now(UTC) + timedelta(days=1)).timestamp())
            loader.loaded_magic.until_ts = future_time

            # 模拟本地文件时间大于等于过期时间（过期）
            expired_time = future_time + 100
            # 模拟远程文件时间小于过期时间（有效）
            valid_time = future_time - 100

            with (
                patch.object(loader, "get_local_file", return_value=(mock_local_content, expired_time)),
                patch.object(loader, "get_remote_file", return_value=(mock_remote_content, valid_time)),
                patch("os.remove") as mock_remove,  # 模拟文件删除
                patch("os.path.exists", return_value=True),  # 确保认为本地文件存在
                patch("builtins.open", mock_open()) as mock_file,  # 模拟文件写入
            ):
                # 调用 get_file，应该删除本地过期文件，获取并保存远程文件
                content = loader.get_file()

                # 验证结果
                assert content == mock_remote_content
                # 验证删除了本地文件
                mock_remove.assert_called_once_with(str(local_file))
                # 验证获取了远程文件
                # 验证写入了远程文件内容到本地
                mock_file.assert_called_with(str(local_file), "wb")
                mock_file().write.assert_called_with(mock_remote_content.encode())
        finally:
            os.chdir(old_cwd)

    def test_load_encrypted_env(self, loader, cipher, decrypted_ex, encrypted_ex):
        """Test loading encrypted env variables"""
        with (
            patch.object(loader, "get_file", return_value=encrypted_ex),
            patch.object(loader, "load_env") as mock_load_env,
        ):
            assert loader.load_encrypted_env()
            mock_load_env.assert_called_once_with(decrypted_ex)
