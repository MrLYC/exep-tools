import os
from unittest.mock import MagicMock, patch

import click
import pytest

from exep_tools.ex import EX
from exep_tools.exep_click import ContextWrapper, ExepGroup


@pytest.fixture
def encrypted_magic():
    """Create a sample encrypted magic string"""
    return "mock_encrypted_magic"


@pytest.fixture
def group(key):
    """Create a ExepGroup instance for testing"""
    return ExepGroup(loader_key=key)


@pytest.fixture
def mock_ex():
    """Create a mock EX instance for testing"""
    return MagicMock(spec=EX, payload={"test_key": "test_value"})


@pytest.fixture
def context_wrapper(mock_ex):
    """Create a ContextWrapper instance for testing"""
    ctx_mock = MagicMock()
    ctx_mock.lookup_default.return_value = None
    return ContextWrapper(ctx_mock, mock_ex)


class TestContextWrapper:
    def test_getattr(self, context_wrapper):
        """Test __getattr__ method of ContextWrapper"""
        # Mock the internal context with a test attribute
        context_wrapper._ContextWrapper__ctx.test_attr = "test_value"

        # Test that the attribute is accessible through the wrapper
        assert context_wrapper.test_attr == "test_value"

    def test_lookup_default_from_ctx(self, context_wrapper):
        """Test lookup_default when value exists in context"""
        # Set up the context to return a value
        context_wrapper._ContextWrapper__ctx.lookup_default.return_value = "ctx_value"

        # Test that the value from context is returned
        assert context_wrapper.lookup_default("test_param") == "ctx_value"
        context_wrapper._ContextWrapper__ctx.lookup_default.assert_called_once_with("test_param", True)

    def test_lookup_default_from_env(self, context_wrapper):
        """Test lookup_default when value exists in environment"""
        # Set up the context to return None
        context_wrapper._ContextWrapper__ctx.lookup_default.return_value = None

        # Test that the value from environment is returned
        assert context_wrapper.lookup_default("test_key") == "test_value"
        context_wrapper._ContextWrapper__ctx.lookup_default.assert_called_once_with("test_key", True)

    def test_lookup_default_not_found(self, context_wrapper):
        """Test lookup_default when value doesn't exist anywhere"""
        # Set up the context to return None
        context_wrapper._ContextWrapper__ctx.lookup_default.return_value = None

        # Test that None is returned for a key that doesn't exist
        assert context_wrapper.lookup_default("non_existent_key") is None
        context_wrapper._ContextWrapper__ctx.lookup_default.assert_called_once_with("non_existent_key", True)

    def test_lookup_default_with_call_false(self, context_wrapper):
        """Test lookup_default with call=False"""
        # Test lookup_default with call=False
        context_wrapper.lookup_default("test_key", call=False)
        context_wrapper._ContextWrapper__ctx.lookup_default.assert_called_once_with("test_key", False)


class TestGroup:
    def test_make_context_invoked_subcommand(self, group, encrypted_magic):
        # 验证 ctx.invoked_subcommand 传递给 Loader
        with patch.dict(os.environ, {"EXEP": encrypted_magic}):
            with patch("exep_tools.exep_click.EXLoader") as mock_loader:
                ctx_mock = MagicMock()
                ctx_mock.invoked_subcommand = "subcmd"
                with patch("click.Group.make_context", return_value=ctx_mock):
                    group.make_context("test-info", ["arg1"])
                    mock_loader.assert_called_once()
                    mock_loader.return_value.load.assert_called_once_with(exep_content=encrypted_magic)

    def test_make_context_loader_init_fail(self, group, encrypted_magic):
        # Loader 初始化异常
        with patch.dict(os.environ, {"EXEP": encrypted_magic}):
            with patch("exep_tools.exep_click.EXLoader", side_effect=Exception("fail")):
                with patch("click.Group.make_context"):
                    # 不抛出异常，流程健壮
                    try:
                        group.make_context("test-info", ["arg1"])
                    except Exception as e:
                        assert str(e) == "fail"

    def test_make_context_exep_invalid(self, group):
        # EXEP 环境变量无效
        with patch.dict(os.environ, {"EXEP": ""}):
            with patch("exep_tools.exep_click.EXLoader") as mock_loader:
                with patch("click.Group.make_context") as mock_super:
                    group.make_context("test-info", ["arg1"])
                    mock_loader.assert_not_called()
                    mock_super.assert_called_once()

    def test_init(self, key):
        """Test ExepGroup initialization"""
        group = ExepGroup(loader_key=key)
        assert group.loader_key == key

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
        with patch.dict(os.environ, {}, clear=True), patch("exep_tools.exep_click.EXLoader") as mock_loader:
            group.make_context("test-info", ["arg1"])
            # EXLoader should not be called
            mock_loader.assert_not_called()

    def test_make_context_with_exep(self, group, encrypted_magic):
        """Test make_context method when EXEP is set"""
        with patch.dict(os.environ, {"EXEP": encrypted_magic}):
            mock_loader = MagicMock()
            with patch("exep_tools.exep_click.EXLoader", return_value=mock_loader) as mock_loader_class:
                group.make_context("test-info", ["arg1"])

                # Verify EXLoader was created with correct parameters
                mock_loader_class.assert_called_once()

                # Verify load method was called
                mock_loader.load.assert_called_once()

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
        """Test integration between ExepGroup and EXLoader"""
        # 创建一个模拟的EXLoader实例，它会返回一个EX对象
        mock_loader_instance = MagicMock()
        mock_ex = MagicMock()
        mock_loader_instance.load.return_value = mock_ex

        with patch.dict(os.environ, {"EXEP": encrypted_magic}):
            with patch("exep_tools.exep_click.EXLoader", return_value=mock_loader_instance):
                group.make_context("test-info", ["arg1"])

                # 验证EXLoader被调用时的参数正确
                assert group.loader_key == key

                # 验证load方法被调用，并且参数正确
                mock_loader_instance.load.assert_called_once_with(exep_content=encrypted_magic)

    def test_make_context_returns_context_wrapper(self, group, encrypted_magic):
        """Test that make_context returns a ContextWrapper when EXEP is set"""
        # Create a mock EX object to be returned by the loader
        mock_ex = MagicMock(spec=EX)
        mock_ex.payload = {"test_key": "test_value"}

        # Create a mock context that will be returned by super().make_context
        ctx_mock = MagicMock()

        with patch.dict(os.environ, {"EXEP": encrypted_magic}):
            # Mock the EXLoader instance and its load method
            mock_loader = MagicMock()
            mock_loader.load.return_value = mock_ex

            with patch("exep_tools.exep_click.EXLoader", return_value=mock_loader):
                with patch("click.Group.make_context", return_value=ctx_mock):
                    result = group.make_context("test-info", ["arg1"])

                    # Verify the result is a ContextWrapper
                    assert isinstance(result, ContextWrapper)

                    # Verify ContextWrapper was initialized with the right arguments
                    assert result._ContextWrapper__ctx is ctx_mock
                    assert result._ContextWrapper__env is mock_ex.payload

    def test_complete_integration_scenario(self, group, encrypted_magic):
        """Test a complete integration scenario with real-like command execution"""
        # 创建一个带有参数的命令行场景
        test_args = ["command", "--option", "value"]

        # 创建带有默认值的上下文
        ctx_mock = MagicMock()
        ctx_mock.params = {"existing_param": "existing_value"}
        ctx_mock.lookup_default.side_effect = lambda name, call=True: ctx_mock.params.get(name) if call else None

        # 创建一个模拟的EX对象，带有额外的环境变量
        mock_ex = MagicMock(spec=EX)
        mock_ex.payload = {"env_param": "env_value"}

        with patch.dict(os.environ, {"EXEP": encrypted_magic}):
            # 设置mock
            mock_loader = MagicMock()
            mock_loader.load.return_value = mock_ex

            with patch("exep_tools.exep_click.EXLoader", return_value=mock_loader):
                with patch("click.Group.make_context", return_value=ctx_mock):
                    # 执行make_context
                    result = group.make_context("test-command", test_args)

                    # 验证返回的是ContextWrapper
                    assert isinstance(result, ContextWrapper)

                    # 测试从上下文中获取值
                    assert result.lookup_default("existing_param") == "existing_value"

                    # 测试从环境变量中获取值
                    assert result.lookup_default("env_param") == "env_value"

                    # 测试不存在的值返回None
                    assert result.lookup_default("non_existent") is None

                    # 验证能否通过__getattr__访问原始上下文的属性
                    assert result.params == ctx_mock.params

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
