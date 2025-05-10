import os
import pytest
from unittest.mock import patch, MagicMock
import click

from devops_exep.click import ExepCommand
from devops_exep.env import Loader


@pytest.fixture
def key():
    """Create a sample key"""
    return "0" * 32


@pytest.fixture
def encrypted_magic():
    """Create a sample encrypted magic string"""
    return "mock_encrypted_magic"


@pytest.fixture
def command(key):
    """Create a ExepCommand instance for testing"""
    return ExepCommand(loader_key=key, name="test-command")


class TestCommand:
    def test_init(self, key):
        """Test ExepCommand initialization"""
        cmd = ExepCommand(loader_key=key, name="test-command")
        assert cmd.loader_key == key
        assert cmd.nonce == ""
        assert cmd.name == "test-command"

    def test_decorator(self, key):
        @click.group(cls=ExepCommand, loader_key=key)
        def passed():
            pass

        @click.group(cls=ExepCommand)
        def normal():
            pass

        assert passed.loader_key == key
        assert normal.loader_key == ""

    def test_make_context_without_exep(self, command):
        """Test make_context method when EXEP is not set"""
        with patch.dict(os.environ, {}, clear=True):
            with patch("devops_exep.click.Loader") as mock_loader:
                result = command.make_context("test-info", [])
                assert command.nonce == "test-info"
                # Loader should not be called
                mock_loader.assert_not_called()

    def test_make_context_with_exep(self, command, encrypted_magic):
        """Test make_context method when EXEP is set"""
        with patch.dict(os.environ, {"EXEP": encrypted_magic}):
            mock_loader = MagicMock()
            with patch(
                "devops_exep.click.Loader", return_value=mock_loader
            ) as mock_loader_class:
                result = command.make_context("test-info", [])
                assert command.nonce == "test-info"

                # Verify Loader was created with correct parameters
                mock_loader_class.assert_called_once_with(
                    key=command.loader_key, nonce="test-info", magic=encrypted_magic
                )

                # Verify load_encrypted_env was called
                mock_loader.load_encrypted_env.assert_called_once()

    def test_make_context_parent_forwarding(self, command):
        """Test that parent is correctly forwarded to super().make_context"""
        with patch.dict(os.environ, {}, clear=True):
            parent = MagicMock()
            with patch("click.Command.make_context") as mock_super_make_context:
                command.make_context("test-info", ["arg1"], parent=parent)
                mock_super_make_context.assert_called_once_with(
                    "test-info", ["arg1"], parent
                )

    def test_make_context_args_forwarding(self, command):
        """Test that args are correctly forwarded to super().make_context"""
        with patch.dict(os.environ, {}, clear=True):
            args = ["arg1", "--option1", "value1"]
            with patch("click.Command.make_context") as mock_super_make_context:
                command.make_context("test-info", args)
                mock_super_make_context.assert_called_once_with("test-info", args, None)

    def test_integration_with_loader(self, command, key, encrypted_magic):
        """Test integration between ExepCommand and Loader"""
        # 创建一个模拟的Loader实例，它会返回True表示成功加载环境变量
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_encrypted_env.return_value = True

        with patch.dict(os.environ, {"EXEP": encrypted_magic}):
            with patch("devops_exep.click.Loader", return_value=mock_loader_instance):
                command.make_context("test-info", [])

                # 验证Loader被调用时的参数正确
                assert command.loader_key == key
                assert command.nonce == "test-info"

                # 验证load_encrypted_env被调用
                mock_loader_instance.load_encrypted_env.assert_called_once()
