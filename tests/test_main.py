import base64
import os
from datetime import datetime

from click.testing import CliRunner

from exep_tools import main


def test_generate_key():
    runner = CliRunner()
    result = runner.invoke(main.generate_key, ["--length", "16"])
    assert result.exit_code == 0
    assert "Generated key:" in result.output
    assert "Key for build:" in result.output
    assert len(result.output.split("Generated key: ")[1].split("\n")[0]) >= 22  # base64长度


def test_encrypt_and_decrypt_data():
    runner = CliRunner()
    key = base64.b64encode(os.urandom(32)).decode()
    nonce = "nonce123"
    data = "hello world"
    # encrypt
    result = runner.invoke(main.encrypt_data, ["-k", key, "-d", data, "-n", nonce])
    assert result.exit_code == 0
    assert "Encrypting data:" in result.output
    encrypted = result.output.split(": ")[1].strip()
    # decrypt
    result2 = runner.invoke(main.decrypt_data, ["-k", key, "-d", encrypted, "-n", nonce])
    assert result2.exit_code == 0
    assert "Decrypting data: hello world" in result2.output


def test_encrypt_file_and_decrypt_file(tmp_path):
    runner = CliRunner()
    key = base64.b64encode(os.urandom(32)).decode()
    nonce = "nonce123"
    plaintext = "foo=bar\nbar=baz"
    input_file = tmp_path / "plain.ex"
    enc_file = tmp_path / "enc.ex"
    dec_file = tmp_path / "dec.ex"
    input_file.write_text(plaintext, encoding="utf-8")
    # encrypt_file
    result = runner.invoke(
        main.encrypt_file,
        ["-k", key, "-i", str(input_file), "-o", str(enc_file), "-n", nonce],
    )
    assert result.exit_code == 0
    assert enc_file.exists()
    # decrypt_file
    result2 = runner.invoke(
        main.decrypt_file,
        ["-k", key, "-i", str(enc_file), "-o", str(dec_file), "-n", nonce],
    )
    assert result2.exit_code == 0
    assert dec_file.exists()
    assert dec_file.read_bytes() == plaintext.encode()


def test_generate_gitlab_exep(tmp_path):
    runner = CliRunner()
    key = base64.b64encode(os.urandom(32)).decode()
    nonce = "nonce123"
    output = tmp_path / "magic.ex"
    result = runner.invoke(
        main.generate_gitlab_exep,
        [
            "-k",
            key,
            "-n",
            nonce,
            "-o",
            str(output),
            "--access-token",
            "tok",
            "--base-url",
            "http://x/",
            "--expire-days",
            "1",
            "--ref-name",
            "main",
            "--remote-file",
            "foo.ex",
            "--local-file",
            "bar.ex",
            "--allow-command",
            "a",
            "--allow-command",
            "b",
            "--disallow-command",
            "c",
            "--disallow-command",
            "d",
            "--environment",
            "FOO=BAR",
        ],
    )
    assert result.exit_code == 0
    assert output.exists()
    # 检查内容可解密且为 EXEP 结构
    from exep_tools.crypto import Cipher
    from exep_tools.ex import decrypt_ex

    cipher = Cipher(base64_key=key, str_nonce=nonce)
    with open(output) as f:
        encrypted_content = f.read()

    # 使用 decrypt_ex 函数解密
    ex = decrypt_ex(encrypted_content, cipher)

    # 检查 meta 部分
    assert ex.meta["name"] == nonce
    assert ex.meta["expire"] > datetime.now().timestamp()

    # 检查 payload 部分
    assert "Bearer tok" in ex.payload["request_headers"]["Authorization"]
    assert "http://x/" in ex.payload["url"]
    assert ex.payload["ref_name"] == "main"
    assert ex.payload["remote_file"] == "foo.ex"
    assert ex.payload["local_file"] == "bar.ex"
    assert ex.payload["allow_commands"] == ["a", "b"]
    assert ex.payload["disallow_commands"] == ["c", "d"]
    assert ex.payload["environments"] == {"FOO": "BAR"}
