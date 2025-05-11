import os
from unittest.mock import MagicMock, patch

import click
import pytest

from exep_tools import ExepGroup


@pytest.fixture
def key():
    """Create a sample key"""
    return "0" * 32


@pytest.fixture
def encrypted_magic():
    """Create a sample encrypted magic string"""
    return "mock_encrypted_magic"


@pytest.fixture
def group(key):
    """Create a ExepGroup instance for testing"""
    return ExepGroup(loader_key=key, name="test-group")


class TestGroup:
    def test_init(self, key):
        """Test ExepGroup initialization"""
        cmd = ExepGroup(loader_key=key, name="test-group")
        assert cmd.loader_key == key
        assert cmd.nonce == ""
        assert cmd.name == "test-group"

    def test_decorator(self, key):
        @click.group(cls=ExepGroup, loader_key=key)
        def passed():
            pass

        @click.group(cls=ExepGroup)
        def normal():
            pass

        assert passed.loader_key == key
        assert normal.loader_key == ""

    def test_make_context_without_exep(self, group):
        """Test make_context method when EXEP is not set"""
        with patch.dict(os.environ, {}, clear=True), patch("exep_tools.exep_click.Loader") as mock_loader:
            group.make_context("test-info", ["arg1"])
            assert group.nonce == "test-info"
            # Loader should not be called
            mock_loader.assert_not_called()

    def test_make_context_with_exep(self, group, encrypted_magic):
        """Test make_context method when EXEP is set"""
        with patch.dict(os.environ, {"EXEP": encrypted_magic}):
            mock_loader = MagicMock()
            with patch("exep_tools.exep_click.Loader", return_value=mock_loader) as mock_loader_class:
                group.make_context("test-info", ["arg1"])
                assert group.nonce == "test-info"

                # Verify Loader was created with correct parameters
                mock_loader_class.assert_called_once_with(
                    key=group.loader_key, nonce="test-info", magic=encrypted_magic
                )

                # Verify load_encrypted_env was called
                mock_loader.load_encrypted_env.assert_called_once()

    def test_make_context_parent_forwarding(self, group):
        """Test that parent is correctly forwarded to super().make_context"""
        with patch.dict(os.environ, {}, clear=True):
            parent = MagicMock()
            with patch("click.Group.make_context") as mock_super_make_context:
                group.make_context("test-info", ["arg1"], parent=parent)
                mock_super_make_context.assert_called_once_with("test-info", ["arg1"], parent)

    def test_make_context_args_forwarding(self, group):
        """Test that args are correctly forwarded to super().make_context"""
        with patch.dict(os.environ, {}, clear=True):
            args = ["arg1", "--option1", "value1"]
            with patch("click.Group.make_context") as mock_super_make_context:
                group.make_context("test-info", args)
                mock_super_make_context.assert_called_once_with("test-info", args, None)

    def test_integration_with_loader(self, group, key, encrypted_magic):
        """Test integration between ExepGroup and Loader"""
        # 创建一个模拟的Loader实例，它会返回True表示成功加载环境变量
        mock_loader_instance = MagicMock()
        mock_loader_instance.load_encrypted_env.return_value = True

        with patch.dict(os.environ, {"EXEP": encrypted_magic}):
            with patch("exep_tools.exep_click.Loader", return_value=mock_loader_instance):
                group.make_context("test-info", ["arg1"])

                # 验证Loader被调用时的参数正确
                assert group.loader_key == key
                assert group.nonce == "test-info"

                # 验证load_encrypted_env被调用
                mock_loader_instance.load_encrypted_env.assert_called_once()
