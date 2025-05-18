import pytest


@pytest.fixture
def key():
    """创建测试密钥"""
    return "0000000000000000"


@pytest.fixture
def nonce():
    """创建测试 nonce"""
    return "yakov"
