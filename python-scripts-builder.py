#!/usr/bin/env python

import os
import shutil
from setuptools.command.build_ext import build_ext
from setuptools import Distribution, Extension
from Cython.Build import cythonize
import inspect
import codecs
import click
import base64
from Crypto.Random import get_random_bytes
from ast_grep_py import SgRoot
import logging

try:
    from devops_tools.crypto_utils import aes
except ImportError:
    pass

logger = logging.getLogger(__name__)

# 编译参数
compile_args = ["-O3"]
link_args = []
source_dir = "devops_tools"
libraries = []
target = "devops-tools"


# 获取所有Python文件作为源文件，但排除测试文件和__pycache__目录
def find_python_files(root_dir=source_dir):
    source_files = []
    for root, dirs, files in os.walk(root_dir):
        if "__pycache__" in root or "tests" in root:
            continue
        for file in files:
            if file.endswith(".py"):
                source_files.append(os.path.join(root, file))
    return source_files


def _load_ex_file(ex_key: str) -> None:
    from dotenv import load_dotenv, find_dotenv
    from devops_tools.crypto_utils import aes
    from devops_tools.remote_utils.file import cache_remote_file
    from io import StringIO
    import codecs
    import os

    ctx = click.get_current_context()
    ex = ""
    exep = os.getenv("EXEP", "")
    cipher = aes.Cipher(
        base64_key=codecs.decode(ex_key, "rot13"), str_nonce=ctx.info_name
    )

    try:
        path = find_dotenv(filename=".ex", usecwd=True) or ".ex"
        url = cipher.decrypt_base64(exep).decode()
        ex = cache_remote_file(url, path)
    except Exception:
        logger.exception("Failed to load ex content")

    if not ex:
        logger.warning("Empty ex content")
        return

    message = cipher.decrypt_base64(ex)
    stream = StringIO(message.decode())

    load_dotenv(stream=stream)
    logger.debug(
        "Decrypted message size: %s, key size: %s, nonce size: %s",
        len(message),
        len(cipher.key),
        len(cipher.nonce),
    )


def inject_load_encrypted_env_file():
    key = os.getenv("EXK")
    if not key:
        return False

    with open("devops_tools/main.py", "r") as f:
        root = SgRoot(f.read(), "python")

    node = root.root()
    run_hook = node.find(
        {
            "rule": {
                "kind": "block",
                "inside": {
                    "kind": "function_definition",
                    "pattern": "def _post_run(): $$$",
                },
            }
        }
    )
    result = node.commit_edits(
        [
            run_hook.replace(
                "\n".join(
                    [
                        "",
                        f"    _load_ex_file('{key}')",
                        f"    {run_hook.text()}",
                        "",
                        inspect.getsource(_load_ex_file),
                    ]
                )
            )
        ]
    )

    with open("devops_tools/main.py", "w") as f:
        f.write(result)
        f.truncate()

    return True


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    if ctx.invoked_subcommand is None:
        ctx.invoke(build)


@cli.command()
def build():
    if not inject_load_encrypted_env_file():
        return

    click.echo("开始构建 Cython 扩展...")

    # 获取源文件
    sources = find_python_files()
    click.echo(f"找到 {len(sources)} 个源文件")

    # 为每个模块创建扩展
    module_names = []
    ext_modules = []

    for source in sources:
        # 确定模块名称
        module_path = os.path.splitext(source)[0]  # 去掉.py扩展名
        module_name = module_path.replace(os.path.sep, ".")
        module_names.append(module_name)

        # 创建扩展
        ext_modules.append(
            Extension(
                module_name,
                [source],
                extra_compile_args=compile_args,
                extra_link_args=link_args,
                include_dirs=[source_dir],
                libraries=libraries,
            )
        )

    # Cythonize所有模块
    cythonized_exts = cythonize(
        ext_modules,
        include_path=[source_dir],
        compiler_directives={
            "language_level": 3,
            "binding": True,
            "embedsignature": True,
        },
    )

    # 使用setuptools构建扩展
    distribution = Distribution({"name": target, "ext_modules": cythonized_exts})

    cmd = build_ext(distribution)
    cmd.ensure_finalized()
    cmd.run()

    click.echo("编译完成，正在复制生成的文件...")

    # 复制编译后的文件
    for output in cmd.get_outputs():
        relative_extension = os.path.relpath(output, cmd.build_lib)
        target_path = relative_extension

        # 确保目标目录存在
        os.makedirs(os.path.dirname(target_path), exist_ok=True)

        # 复制文件
        shutil.copyfile(output, target_path)

        # 设置权限
        mode = os.stat(target_path).st_mode
        mode |= (mode & 0o444) >> 2
        os.chmod(target_path, mode)

        click.echo(f"已复制: {output} -> {target_path}")

    click.echo("构建成功完成!")


@cli.command()
@click.option("--length", default=32, help="Length of the generated key")
def generate_ex_key(length: int):
    key = get_random_bytes(length)
    key = base64.b64encode(key).decode()

    click.echo(f"Generated key: {key}")
    click.echo(f"Key for build: {codecs.encode(key, 'rot13')}")


@cli.command()
@click.option("-k", "--key", prompt="Key", help="Key for encrypting .ex")
@click.option("-d", "--data", prompt="Data", help="Data to encrypt")
@click.option(
    "-n", "--nonce", default=target, help="Nonce for AES encryption (optional)"
)
def encrypt_data(key: str, data: str, nonce: str):
    cipher = aes.Cipher(base64_key=key, str_nonce=nonce)
    encrypted = cipher.encrypt_base64(data.encode("utf-8"))
    click.echo(f"Encrypting data: {encrypted.decode()}")


@cli.command()
@click.option("-k", "--key", prompt="Key", help="Key for decrypting .ex")
@click.option("-d", "--data", prompt="Data", help="Data to decrypt")
@click.option(
    "-n", "--nonce", default=target, help="Nonce for AES encryption (optional)"
)
def decrypt_data(key: str, data: str, nonce: str):
    cipher = aes.Cipher(base64_key=key, str_nonce=nonce)
    decrypted = cipher.decrypt_base64(data)
    click.echo(f"Decrypting data: {decrypted.decode()}")


@cli.command()
@click.option("-k", "--key", prompt="Key", help="Key for decrypting .ex")
@click.option(
    "-i", "--input-file", prompt="Input file", help="Path to the encrypted .ex file"
)
@click.option(
    "-o", "--output", prompt="Output file", help="Path to save the decrypted .ex file"
)
@click.option(
    "-n", "--nonce", default=target, help="Nonce for AES encryption (optional)"
)
def encrypt_ex(key: str, input_file: str, output: str, nonce: str):
    with open(input_file, "rt") as f:
        plaintext = f.read()

    cipher = aes.Cipher(base64_key=key, str_nonce=nonce)
    encrypted = cipher.encrypt_base64(plaintext.encode())

    with open(output, "wb") as f:
        f.write(encrypted)

    click.echo(f"Encrypted file saved to {output}")


@cli.command()
@click.option("-k", "--key", prompt="Key", help="Key for decrypting .ex")
@click.option(
    "-i", "--input-file", prompt="Input file", help="Path to the encrypted .ex file"
)
@click.option(
    "-o", "--output", prompt="Output file", help="Path to save the decrypted .ex file"
)
@click.option(
    "-n", "--nonce", default=target, help="Nonce for AES encryption (optional)"
)
def decrypt_ex(key: str, input_file: str, output: str, nonce: str):
    with open(input_file, "rb") as f:
        encrypted = f.read()

    cipher = aes.Cipher(base64_key=key, str_nonce=nonce)
    plaintext = cipher.decrypt_base64(encrypted)

    with open(output, "wb") as f:
        f.write(plaintext)

    click.echo(f"Decrypted file saved to {output}")


if __name__ == "__main__":
    cli()
