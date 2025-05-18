import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest

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
        "meta": {"expire": future_time},
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


class TestEXLoader:
    def test_load_from_exep(self, cipher, encrypted_exep, ex_data, requests_mock):
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
            mock_save.assert_called_once_with(encrypted_ex)

    def test_load_from_local(self, cipher, encrypted_ex, ex_data, tmp_path):
        """测试从本地加载 EX"""
        # 创建临时 EX 文件
        ex_file = tmp_path / ".ex"
        with open(ex_file, "w") as f:
            f.write(encrypted_ex)

        # 创建 EXLoader 和修改搜索路径
        loader = EXLoader(cipher)
        loader._ex_search_paths = [str(ex_file)]

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

        # 创建 EXLoader 和修改搜索路径
        loader = EXLoader(cipher)
        loader._ex_search_paths = [str(ex_file)]

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
                mock_local.assert_called_once()
                mock_exep.assert_called_once_with(encrypted_exep)

        # 情况2: 本地有文件
        ex_obj = MagicMock()
        with patch.object(loader, "load_from_local", return_value=ex_obj) as mock_local:
            with patch.object(loader, "load_from_exep") as mock_exep:
                result = loader.load(encrypted_exep)
                mock_local.assert_called_once()
                mock_exep.assert_not_called()
                assert result == ex_obj

        # 情况3: 本地无文件，无 EXEP
        with patch.object(loader, "load_from_local", return_value=None):
            with pytest.raises(RuntimeError, match="无法加载 EX"):
                loader.load()
