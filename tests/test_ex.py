import json
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest
import requests

from exep_tools.crypto import Cipher
from exep_tools.ex import EX, EXEP, EXLoader


@pytest.fixture
def cipher(key, nonce):
    """创建测试用的 Cipher 实例"""
    return Cipher(str_key=key, str_nonce=nonce)


@pytest.fixture
def ex_data():
    """创建测试用的 EX 数据"""
    # 设置为未来时间，确保测试时没有过期
    future_time = int((datetime.now(UTC) + timedelta(days=1)).timestamp())
    return {"meta": {"expire": future_time}, "payload": {"key": "value"}}


@pytest.fixture
def exep_data():
    """创建测试用的 EXEP 数据"""
    # 设置为未来时间，确保测试时没有过期
    future_time = int((datetime.now(UTC) + timedelta(days=2)).timestamp())
    return {
        "meta": {"expire": future_time, "name": "test_exep"},
        "payload": {
            "url": "https://example.com/ex",
            "request_headers": {"Authorization": "Bearer test"},
            "queries": {"param": "value"},
            "response_headers": ["Content-Type"],
        },
    }


@pytest.fixture
def encrypted_ex(cipher, ex_data):
    """创建加密的 EX 内容"""
    ex_json = json.dumps(ex_data)
    return cipher.encrypt_base64(ex_json.encode()).decode()


@pytest.fixture
def encrypted_exep(cipher, exep_data):
    """创建加密的 EXEP 内容"""
    exep_json = json.dumps(exep_data)
    return cipher.encrypt_base64(exep_json.encode()).decode()


class TestEX:
    def test_from_json(self, ex_data):
        """测试从 JSON 创建 EX 对象"""
        ex_json = json.dumps(ex_data)
        ex = EX.from_json(ex_json)

        assert ex.meta == ex_data["meta"]
        assert ex.payload == ex_data["payload"]
        assert ex.expire == ex_data["meta"]["expire"]

    def test_to_json(self, ex_data):
        """测试将 EX 对象转换为 JSON"""
        ex = EX(meta=ex_data["meta"], payload=ex_data["payload"])
        ex_json = ex.to_json()

        # 反序列化比较
        assert json.loads(ex_json) == ex_data

    def test_is_expired(self):
        """测试过期检查"""
        now = int(datetime.now(UTC).timestamp())
        past_time = now - 1000
        future_time = now + 1000

        expired_ex = EX(meta={"expire": past_time}, payload={})
        valid_ex = EX(meta={"expire": future_time}, payload={})

        assert expired_ex.is_expired(now) is True
        assert valid_ex.is_expired(now) is False

    def test_excrypt_and_decrypt_ex(self, cipher, ex_data):
        """测试EX对象的加密和解密"""
        from exep_tools.ex import decrypt_ex, excrypt_ex

        # 创建EX对象
        ex = EX(meta=ex_data["meta"], payload=ex_data["payload"])

        # 加密
        encrypted = excrypt_ex(ex, cipher)
        assert isinstance(encrypted, str)
        assert len(encrypted) > 0

        # 解密
        decrypted = decrypt_ex(encrypted, cipher)
        assert isinstance(decrypted, EX)
        assert decrypted.meta == ex.meta
        assert decrypted.payload == ex.payload


class TestEXEP:
    def test_from_json(self, exep_data):
        """测试从 JSON 创建 EXEP 对象"""
        exep_json = json.dumps(exep_data)
        exep = EXEP.from_json(exep_json)

        assert exep.meta == exep_data["meta"]
        assert exep.payload == exep_data["payload"]
        assert exep.url == exep_data["payload"]["url"]
        assert exep.request_headers == exep_data["payload"]["request_headers"]
        assert exep.queries == exep_data["payload"]["queries"]
        assert exep.response_headers == exep_data["payload"]["response_headers"]
        assert exep.expire == exep_data["meta"]["expire"]
        assert exep.name == exep_data["meta"]["name"]
        assert exep.filename == f"{exep_data['meta']['name']}.ex"

    def test_name_and_path(self):
        """测试 name 和 path 属性"""
        # 测试有名称的情况
        exep_with_name = EXEP(meta={"name": "test"}, payload={})
        assert exep_with_name.name == "test"
        assert exep_with_name.filename == "test.ex"

        # 测试无名称的情况
        exep_without_name = EXEP(meta={}, payload={})
        assert exep_without_name.name == ""
        assert exep_without_name.filename == ".ex"


class TestEXLoader:
    def test_load_from_exep(self, cipher, encrypted_exep, exep_data, ex_data, requests_mock):
        """测试通过 EXEP 加载 EX"""
        # 模拟 EX 请求响应
        ex_url = "https://example.com/ex"
        ex_json = json.dumps(ex_data)
        encrypted_ex = cipher.encrypt_base64(ex_json.encode()).decode()

        requests_mock.get(
            ex_url,
            text=encrypted_ex,
            status_code=200,
            headers={
                "Content-Type": "application/json",
                "Date": datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S GMT"),
            },
        )

        # 创建 EXLoader 并加载 EX
        loader = EXLoader(cipher)

        # 模拟保存到本地
        with patch.object(loader, "_save_to_local") as mock_save:
            ex = loader.load_from_exep(encrypted_exep)

            assert ex.meta == ex_data["meta"]
            assert ex.payload == ex_data["payload"]
            mock_save.assert_called_once_with(encrypted_ex, f"{exep_data['meta']['name']}.ex")

    def test_load_from_local(self, cipher, encrypted_ex, ex_data, tmp_path):
        """测试从本地加载 EX"""
        # 创建临时 EX 文件
        ex_file = tmp_path / ".ex"
        with open(ex_file, "w") as f:
            f.write(encrypted_ex)

        # 创建 EXLoader 并重写 _get_search_paths 方法
        loader = EXLoader(cipher)
        # 重写方法来返回我们的测试路径
        loader._get_search_paths = lambda filename=None: [str(ex_file)]

        # 加载本地 EX
        ex = loader.load_from_local()

        assert ex is not None
        assert ex.meta == ex_data["meta"]
        assert ex.payload == ex_data["payload"]

    def test_load_expired_local(self, cipher, tmp_path):
        """测试加载过期的本地 EX"""
        # 创建过期的 EX 数据
        past_time = int((datetime.now(UTC) - timedelta(days=1)).timestamp())
        expired_ex_data = {"meta": {"expire": past_time}, "payload": {"key": "value"}}

        # 加密 EX 数据
        ex_json = json.dumps(expired_ex_data)
        encrypted_ex = cipher.encrypt_base64(ex_json.encode()).decode()

        # 创建临时 EX 文件
        ex_file = tmp_path / ".ex"
        with open(ex_file, "w") as f:
            f.write(encrypted_ex)

        # 创建 EXLoader 并重写 _get_search_paths 方法
        loader = EXLoader(cipher)
        # 重写方法来返回我们的测试路径
        loader._get_search_paths = lambda filename=None: [str(ex_file)]

        # 模拟文件删除
        with patch("os.remove") as mock_remove:
            ex = loader.load_from_local()

            assert ex is None
            mock_remove.assert_called_once_with(str(ex_file))

    def test_load_combined(self, cipher, encrypted_exep, encrypted_ex, tmp_path):
        """测试综合加载逻辑"""
        # 创建 EXLoader
        loader = EXLoader(cipher)

        # 情况1: 本地无文件，提供 EXEP
        with patch.object(loader, "load_from_local", return_value=None) as mock_local:
            with patch.object(loader, "load_from_exep") as mock_exep:
                loader.load(encrypted_exep)
                mock_local.assert_called_once_with(None)  # 传入默认文件名参数
                mock_exep.assert_called_once_with(encrypted_exep)

        # 情况2: 本地有文件
        ex_obj = MagicMock()
        with patch.object(loader, "load_from_local", return_value=ex_obj) as mock_local:
            with patch.object(loader, "load_from_exep") as mock_exep:
                result = loader.load(encrypted_exep, "custom.ex")
                mock_local.assert_called_once_with("custom.ex")
                mock_exep.assert_not_called()
                assert result == ex_obj

        # 情况3: 本地无文件，无 EXEP
        with patch.object(loader, "load_from_local", return_value=None):
            with pytest.raises(RuntimeError, match="无法加载 EX"):
                loader.load()

    def test_save_to_local_with_symlinks(self, cipher, ex_data, tmp_path):
        """测试保存 EX 到本地并创建符号链接"""
        # 创建加密的 EX 数据
        ex_json = json.dumps(ex_data)
        encrypted_ex = cipher.encrypt_base64(ex_json.encode()).decode()

        # 创建临时目录作为搜索路径
        primary_path = tmp_path / "primary" / ".ex"
        secondary_path = tmp_path / "secondary" / ".ex"

        # 确保父目录存在
        primary_path.parent.mkdir(parents=True, exist_ok=True)
        secondary_path.parent.mkdir(parents=True, exist_ok=True)

        # 创建 EXLoader 并重写 _get_search_paths 方法
        loader = EXLoader(cipher)
        # 重写方法来返回我们的测试路径
        loader._get_search_paths = lambda filename=None: [str(primary_path), str(secondary_path)]

        # 保存 EX 到本地
        loader._save_to_local(encrypted_ex)

        # 验证主文件是否正确创建
        assert primary_path.exists()
        assert primary_path.read_text() == encrypted_ex

        # 验证符号链接是否正确创建
        assert secondary_path.exists()
        assert secondary_path.is_symlink()
        assert secondary_path.resolve() == primary_path.resolve()

    def test_fetch_ex_from_exep_error_handling(self, cipher, exep_data, requests_mock):
        """测试_fetch_ex_from_exep方法的错误处理"""
        exep = EXEP.from_json(json.dumps(exep_data))
        loader = EXLoader(cipher)

        # 情况1: 请求异常
        requests_mock.get(exep.url, exc=requests.RequestException("Connection error"))
        with pytest.raises(RuntimeError, match="请求 EX 失败"):
            loader._fetch_ex_from_exep(exep)

        # 情况2: 状态码错误
        requests_mock.get(exep.url, status_code=404, text="Not Found")
        with pytest.raises(RuntimeError, match="请求 EX 失败"):
            loader._fetch_ex_from_exep(exep)

        # 情况3: 缺少必要的响应头
        requests_mock.get(
            exep.url,
            status_code=200,
            text="success",
            headers={"Date": datetime.now(UTC).strftime("%a, %d %b %Y %H:%M:%S GMT")},
        )
        with pytest.raises(RuntimeError, match="响应头缺少必需的字段"):
            loader._fetch_ex_from_exep(exep)

        # 情况4: 缺少Date头
        exep_no_header = EXEP(
            meta=exep.meta,
            payload={**exep.payload, "response_headers": []},
        )
        requests_mock.get(
            exep.url,
            status_code=200,
            text="success",
            headers={},
        )
        with pytest.raises(RuntimeError, match="响应头缺少 Date 字段"):
            loader._fetch_ex_from_exep(exep_no_header)

    def test_load_from_exep_expired(self, cipher, exep_data):
        """测试加载过期的EXEP"""
        # 创建过期的EXEP数据
        past_time = int((datetime.now(UTC) - timedelta(days=1)).timestamp())
        expired_exep_data = {**exep_data, "meta": {**exep_data["meta"], "expire": past_time}}

        # 加密EXEP数据
        exep_json = json.dumps(expired_exep_data)
        encrypted_exep = cipher.encrypt_base64(exep_json.encode()).decode()

        # 创建EXLoader
        loader = EXLoader(cipher)

        # 测试加载过期的EXEP
        with pytest.raises(RuntimeError, match="EXEP 已过期"):
            loader.load_from_exep(encrypted_exep)

    def test_get_file_timestamp(self, cipher, tmp_path):
        """测试_get_file_timestamp方法"""
        # 创建测试文件
        test_file = tmp_path / "test_file"
        with open(test_file, "w") as f:
            f.write("test content")

        # 创建EXLoader
        loader = EXLoader(cipher)

        # 获取文件时间戳
        timestamp = loader._get_file_timestamp(str(test_file))

        # 验证时间戳是整数且大于0
        assert isinstance(timestamp, int)
        assert timestamp > 0

        # 验证时间戳至少等于当前时间
        current_time = int(time.time())
        assert timestamp >= current_time

    def test_save_ex_to_local(self, cipher, ex_data, tmp_path):
        """测试save_ex_to_local方法"""
        # 创建EX对象
        ex = EX(meta=ex_data["meta"], payload=ex_data["payload"])

        # 创建测试目录作为搜索路径
        test_dir = tmp_path / "test_dir"
        test_dir.mkdir()
        test_file = test_dir / "test.ex"

        # 创建EXLoader并修改_get_search_paths方法
        loader = EXLoader(cipher)
        loader._get_search_paths = lambda filename=None: [str(test_file)]

        # 模拟_save_to_local方法
        with patch.object(loader, "_save_to_local") as mock_save:
            # 保存EX到本地
            loader.save_ex_to_local(ex, "test.ex")

            # 验证_save_to_local方法被正确调用
            mock_save.assert_called_once()

            # 获取调用参数
            encrypted_content = mock_save.call_args[0][0]
            filename = mock_save.call_args[0][1]

            # 解密内容并验证
            decrypted_ex = loader.cipher.decrypt_base64(encrypted_content).decode()
            assert json.loads(decrypted_ex)["meta"] == ex.meta
            assert json.loads(decrypted_ex)["payload"] == ex.payload
            assert filename == "test.ex"

    def test_symlink_error_handling(self, cipher, tmp_path, caplog):
        """测试创建符号链接时的错误处理"""
        import logging

        # 捕获日志
        caplog.set_level(logging.INFO)

        # 创建临时目录作为搜索路径
        primary_path = tmp_path / "primary" / ".ex"
        secondary_path = tmp_path / "secondary" / ".ex"

        # 确保父目录存在
        primary_path.parent.mkdir(parents=True, exist_ok=True)
        secondary_path.parent.mkdir(parents=True, exist_ok=True)

        # 创建已存在的文件（非符号链接）
        with open(secondary_path, "w") as f:
            f.write("existing content")

        # 创建EXLoader并修改_get_search_paths方法
        loader = EXLoader(cipher)
        loader._get_search_paths = lambda filename=None: [str(primary_path), str(secondary_path)]

        # 模拟os.symlink抛出异常
        with patch("os.symlink", side_effect=OSError("Symlink error")):
            # 保存到本地
            loader._save_to_local("encrypted content")

            # 验证主文件已创建
            assert primary_path.exists()
            assert primary_path.read_text() == "encrypted content"

            # 验证日志记录了错误
            assert "创建符号链接失败" in caplog.text

    def test_load_from_local_exception_handling(self, cipher, tmp_path, caplog):
        """测试从本地加载时的异常处理"""
        import logging

        # 捕获日志
        caplog.set_level(logging.INFO)

        # 创建无效的加密内容
        invalid_content = "invalid encrypted content"

        # 创建临时文件
        ex_file = tmp_path / ".ex"
        with open(ex_file, "w") as f:
            f.write(invalid_content)

        # 创建EXLoader并重写_get_search_paths方法
        loader = EXLoader(cipher)
        loader._get_search_paths = lambda filename=None: [str(ex_file)]

        # 从本地加载
        result = loader.load_from_local()

        # 验证结果为None且记录了异常
        assert result is None
        assert "加载本地 EX 文件失败" in caplog.text
