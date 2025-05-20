import os
from unittest.mock import MagicMock, patch

import pytest

from exep_tools.ex import EX
from exep_tools.exep_click import ExGroup


@pytest.fixture
def encrypted_magic():
    """Create a sample encrypted magic string"""
    return "mock_encrypted_magic"


@pytest.fixture
def group(key):
    """Create a ExGroup instance for testing"""
    return ExGroup(loader_key=key)


@pytest.fixture
def mock_ex():
    """Create a mock EX instance for testing"""
    return MagicMock(spec=EX, payload={"test_key": "test_value"})


class TestGroup:
    def test_make_context_invoked_subcommand(self, group, encrypted_magic):
        # 验证 make_context 方法正确处理 info_name
        with patch.dict(os.environ, {"EXEP": encrypted_magic, "EXLN": "example"}):
            with patch("exep_tools.exep_click.generate_nonce") as mock_generate_nonce:
                with patch("exep_tools.exep_click.EXLoader") as mock_loader_class:
                    ctx_mock = MagicMock()
                    ctx_mock.info_name = "subcmd"
                    with patch("click.Group.make_context", return_value=ctx_mock):
                        group.make_context("subcmd", ["arg1"])
                        mock_loader_class.assert_called_once()
                        mock_generate_nonce.assert_called_once_with("example", "subcmd")
                        mock_loader_class.return_value.load.assert_called_once_with(exep_content=encrypted_magic)

    def test_make_context_loader_init_fail(self, group, encrypted_magic):
        # Cipher 初始化异常
        with patch.dict(os.environ, {"EXEP": encrypted_magic}):
            with patch("exep_tools.exep_click.Cipher", side_effect=Exception("cipher fail")):
                with patch("click.Group.make_context"):
                    # 应该抛出异常
                    with pytest.raises(Exception, match="cipher fail"):
                        group.make_context("test-info", ["arg1"])

    def test_make_context_exep_invalid(self, group):
        # EXEP 环境变量无效
        with patch.dict(os.environ, {"EXEP": ""}):
            with patch("exep_tools.exep_click.EXLoader") as mock_loader:
                with patch("click.Group.make_context") as mock_super:
                    group.make_context("test-info", ["arg1"])
                    mock_loader.assert_not_called()
                    mock_super.assert_called_once()

    def test_make_context_without_exep(self, group):
        """Test make_context method when EXEP is not set"""
        with patch.dict(os.environ, {}, clear=True), patch("exep_tools.exep_click.EXLoader") as mock_loader:
            group.make_context("test-info", ["arg1"])
            # EXLoader should not be called
            mock_loader.assert_not_called()

    def test_make_context_with_exep(self, group, encrypted_magic):
        """Test make_context method when EXEP is set"""
        with patch.dict(os.environ, {"EXEP": encrypted_magic}):
            mock_loader = MagicMock()
            mock_ex = MagicMock(spec=EX)
            mock_ex.payload = {"test_key": "test_value"}
            mock_loader.load.return_value = mock_ex

            with patch("exep_tools.exep_click.EXLoader", return_value=mock_loader) as mock_loader_class:
                with patch("exep_tools.exep_click.generate_nonce", return_value="mocked_nonce"):
                    ctx = group.make_context("test-info", ["arg1"])

                    # Verify EXLoader was created with correct parameters
                    mock_loader_class.assert_called_once()

                    # Verify load method was called
                    mock_loader.load.assert_called_once_with(exep_content=encrypted_magic)

                    # Verify ctx.obj was set to ex.payload
                    assert ctx.obj == mock_ex.payload

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
        """Test integration between ExGroup and EXLoader"""
        # 创建一个模拟的EX实例，用于测试
        mock_ex = MagicMock(spec=EX)
        mock_ex.payload = {"test_key": "test_value"}

        # 模拟loader返回的EX实例
        mock_loader_instance = MagicMock()
        mock_loader_instance.load.return_value = mock_ex

        with patch.dict(os.environ, {"EXEP": encrypted_magic, "EXLN": "test_nonce"}):
            with patch("exep_tools.exep_click.EXLoader", return_value=mock_loader_instance):
                with patch("exep_tools.exep_click.generate_nonce", return_value="generated_nonce"):
                    with patch("exep_tools.exep_click.Cipher") as mock_cipher:
                        ctx = group.make_context("test-info", ["arg1"])

                        # 验证Cipher被正确初始化
                        mock_cipher.assert_called_once_with(rot13_key=key, str_nonce="generated_nonce")

                        # 验证load方法被调用，并且参数正确
                        mock_loader_instance.load.assert_called_once_with(exep_content=encrypted_magic)

                        # 验证ctx.obj被正确设置
                        assert ctx.obj == {"test_key": "test_value"}

    def test_complete_integration_scenario(self, group, encrypted_magic):
        """Test a complete integration scenario with real-like command execution"""
        # 创建一个带有参数的命令行场景
        test_args = ["command", "--option", "value"]

        # 创建带有默认值的上下文
        ctx_mock = MagicMock()
        ctx_mock.info_name = "command"

        # 创建一个模拟的EX对象，带有额外的环境变量
        mock_ex = MagicMock(spec=EX)
        mock_ex.payload = {"env_param": "env_value"}

        with patch.dict(os.environ, {"EXEP": encrypted_magic}):
            # 设置mock
            with patch("click.Group.make_context", return_value=ctx_mock):
                with patch("exep_tools.exep_click.EXLoader") as mock_loader_class:
                    mock_loader_instance = MagicMock()
                    mock_loader_instance.load.return_value = mock_ex
                    mock_loader_class.return_value = mock_loader_instance

                    with patch("exep_tools.exep_click.generate_nonce", return_value="generated_nonce"):
                        # 执行make_context
                        result = group.make_context("command", test_args)

                        # 验证ctx.obj被正确设置为ex.payload
                        assert result.obj == mock_ex.payload

    def test_exloader_load_exception(self, group, encrypted_magic):
        """Test behavior when EXLoader.load() raises an exception"""
        with patch.dict(os.environ, {"EXEP": encrypted_magic}):
            # 创建一个mock加载器，其load方法会抛出异常
            mock_loader = MagicMock()
            mock_loader.load.side_effect = Exception("Load failed")

            with patch("exep_tools.exep_click.EXLoader", return_value=mock_loader):
                with patch("click.Group.make_context") as mock_make_context:
                    # 期望异常被传递出来
                    with pytest.raises(Exception, match="Load failed"):
                        group.make_context("test-info", ["arg1"])

                    # 确认super().make_context被调用了
                    mock_make_context.assert_called_once()


class TestExDelegator:
    def test_getattr_with_empty_obj(self):
        """Test behavior when context.obj is empty"""
        from exep_tools.exep_click import DELEGATOR

        # 创建一个模拟上下文
        ctx_mock = MagicMock()
        ctx_mock.obj = None

        with patch("click.get_current_context", return_value=ctx_mock):
            # 当context.obj为None时，应该返回None
            assert DELEGATOR.any_attribute() is None

    def test_getattr_with_obj(self):
        """Test behavior when context.obj has value"""
        from exep_tools.exep_click import DELEGATOR

        # 创建一个模拟上下文
        ctx_mock = MagicMock()
        ctx_mock.obj = {"test_key": "test_value"}

        with patch("click.get_current_context", return_value=ctx_mock):
            # 当属性存在于context.obj中时，应该返回属性值
            assert DELEGATOR.test_key() == "test_value"

            # 当属性不存在于context.obj中时，应该返回None
            assert DELEGATOR.non_existent() is None
