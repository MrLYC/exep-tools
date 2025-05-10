import os
import tempfile
import shutil
import pytest
from pathlib import Path

from devops_exep.cython import Builder


@pytest.fixture
def temp_dirs():
    """创建测试和构建用的临时目录"""
    # 创建临时目录
    temp_dir = tempfile.mkdtemp(prefix="cython_test_")
    target_dir = tempfile.mkdtemp(prefix="cython_build_")

    # 返回创建的临时目录
    yield temp_dir, target_dir

    # 测试结束后清理临时目录
    shutil.rmtree(temp_dir, ignore_errors=True)
    shutil.rmtree(target_dir, ignore_errors=True)


@pytest.fixture
def test_files(temp_dirs):
    """创建测试用的Python文件"""
    temp_dir, _ = temp_dirs

    # 创建示例模块结构
    module_dir = os.path.join(temp_dir, "sample_module")
    os.makedirs(module_dir, exist_ok=True)

    # 创建__init__.py
    with open(os.path.join(module_dir, "__init__.py"), "w") as f:
        f.write("# Sample module\n")

    # 创建简单的Python文件
    with open(os.path.join(module_dir, "math_funcs.py"), "w") as f:
        f.write(
            """
def add(a, b):
    return a + b

def multiply(a, b):
    return a * b
"""
        )

    # 创建另一个文件
    with open(os.path.join(module_dir, "string_funcs.py"), "w") as f:
        f.write(
            """
def concat(a, b):
    return str(a) + str(b)

def repeat(s, n):
    return s * n
"""
        )

    # 创建测试目录 (应该被排除)
    test_dir = os.path.join(temp_dir, "tests")
    os.makedirs(test_dir, exist_ok=True)
    with open(os.path.join(test_dir, "test_math.py"), "w") as f:
        f.write("# Test file that should be ignored\n")

    return temp_dir


def test_find_python_files(test_files):
    """测试查找Python文件的功能"""
    temp_dir = test_files
    builder = Builder(root_dir=temp_dir, target="sample_module")
    files = builder.find_python_files()

    # 应该找到3个Python文件 (不包括tests目录中的文件)
    assert len(files) == 3  # __init__.py, math_funcs.py, string_funcs.py

    # 验证文件路径
    file_names = [os.path.basename(f) for f in files]
    assert "__init__.py" in file_names
    assert "math_funcs.py" in file_names
    assert "string_funcs.py" in file_names

    # 确保测试目录中的文件没有被包含
    for file in files:
        assert "tests" not in file


def test_build(temp_dirs, test_files):
    """测试Cython构建过程"""
    # 注意: 这个测试可能会很慢，因为实际上要进行Cython编译
    temp_dir, target_dir = temp_dirs

    output_dir = os.path.join(target_dir, "output")
    os.makedirs(output_dir, exist_ok=True)
    builder = Builder(
        root_dir=temp_dir,
        target="sample_module",
        output_dir=output_dir,
    )
    builder.build()

    # 检查输出目录中是否有编译后的文件
    compiled_files = []
    for root, _, files in os.walk(output_dir):
        for file in files:
            if file.endswith(".so") or file.endswith(".pyd"):
                compiled_files.append(os.path.join(root, file))

    # 检查是否有任何生成的文件
    all_generated_files = compiled_files
    assert all_generated_files, "没有找到任何编译后的文件"

    # 打印找到的文件以便调试
    print(f"找到的编译文件: {all_generated_files}")
