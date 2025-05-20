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

    def test_delegator_usage_in_command(self):
        """测试DELEGATOR在实际Command中的使用"""
        import click
        from click.testing import CliRunner

        from exep_tools.exep_click import DELEGATOR

        # 创建一个使用DELEGATOR的命令
        @click.command()
        def cmd():
            value = DELEGATOR.test_key()
            click.echo(f"Delegated value: {value}")

        # 测试没有context.obj的情况
        runner = CliRunner()
        result = runner.invoke(cmd)
        assert result.exit_code == 0
        assert "Delegated value: None" in result.output

        # 测试有context.obj的情况
        runner = CliRunner()
        ctx_obj = {"test_key": "delegated_value"}
        result = runner.invoke(cmd, obj=ctx_obj)
        assert result.exit_code == 0
        assert "Delegated value: delegated_value" in result.output


class TestExOption:
    def test_option_default(self):
        """测试ExOption获取默认值"""
        import click

        from exep_tools.exep_click import ExOption

        # 创建一个模拟的上下文
        ctx = MagicMock(spec=click.Context)
        ctx.obj = {"test_option": "value_from_obj"}

        # 创建一个ExOption实例
        option = ExOption(["--test-option"])
        option.name = "test_option"

        # 模拟超类方法返回None
        with patch.object(click.Option, "get_default", return_value=None):
            # 测试从ctx.obj获取值
            value = option.get_default(ctx)
            assert value == "value_from_obj"

        # 测试没有ctx.obj的情况
        ctx.obj = None
        with patch.object(click.Option, "get_default", return_value=None):
            value = option.get_default(ctx)
            assert value is None

        # 测试超类方法返回非None值的情况
        with patch.object(click.Option, "get_default", return_value="default_value"):
            value = option.get_default(ctx)
            assert value == "default_value"

    def test_option_in_command(self):
        """测试ExOption在实际Command中的使用"""
        import click
        from click.testing import CliRunner

        from exep_tools.exep_click import ExOption

        # 创建一个使用ExOption的命令
        @click.command()
        @click.option("--test-option", cls=ExOption)
        def cmd(test_option):
            click.echo(f"Option value: {test_option}")

        # 测试命令行参数传递值
        runner = CliRunner()
        result = runner.invoke(cmd, ["--test-option", "cli_value"])
        assert result.exit_code == 0
        assert "Option value: cli_value" in result.output

        # 测试从context.obj获取值
        runner = CliRunner()
        ctx_obj = {"test_option": "context_value"}
        result = runner.invoke(cmd, obj=ctx_obj)
        assert result.exit_code == 0
        assert "Option value: context_value" in result.output

        # 测试既没有命令行参数也没有context.obj值的情况
        runner = CliRunner()
        result = runner.invoke(cmd)
        assert result.exit_code == 0
        assert "Option value: None" in result.output

    def test_integration_exgroup_with_exoption(self, key, encrypted_magic):
        """测试ExGroup, ExOption和DELEGATOR的集成"""
        import click
        from click.testing import CliRunner

        from exep_tools.exep_click import DELEGATOR, ExGroup, ExOption

        # 创建一个使用所有组件的命令组
        @click.group(cls=ExGroup, loader_key=key)
        def cli():
            pass

        @cli.command()
        @click.option("--test-option", cls=ExOption)
        def cmd(test_option):
            # 从option获取
            click.echo(f"Option value: {test_option}")
            # 从DELEGATOR获取
            delegated = DELEGATOR.test_option()
            click.echo(f"Delegated value: {delegated}")

        # 设置模拟的EX对象和环境变量
        mock_ex = MagicMock(spec=EX)
        mock_ex.payload = {"test_option": "payload_value"}

        with patch("exep_tools.exep_click.generate_nonce", return_value="test_nonce"):
            with patch("exep_tools.exep_click.Cipher"):
                with patch("exep_tools.exep_click.EXLoader") as mock_loader:
                    mock_loader.return_value.load.return_value = mock_ex

                    # 测试命令行参数优先级高于payload
                    runner = CliRunner()
                    with patch.dict(os.environ, {"EXEP": encrypted_magic}):
                        result = runner.invoke(cli, ["cmd", "--test-option", "cli_value"])
                        assert result.exit_code == 0
                        assert "Option value: cli_value" in result.output
                        assert "Delegated value: payload_value" in result.output

                    # 测试从payload获取值
                    runner = CliRunner()
                    with patch.dict(os.environ, {"EXEP": encrypted_magic}):
                        result = runner.invoke(cli, ["cmd"])
                        assert result.exit_code == 0
                        assert "Option value: payload_value" in result.output
                        assert "Delegated value: payload_value" in result.output
