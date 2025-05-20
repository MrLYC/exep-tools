import base64
import os
import time

from click.testing import CliRunner

from exep_tools import main


def test_generate_key():
    runner = CliRunner()
    result = runner.invoke(main.generate_key, ["--length", "16"])
    assert result.exit_code == 0
    assert "EXK:" in result.output
    assert "EXLK:" in result.output
    key_output = result.output.split("EXK: ")[1].split("\n")[0]
    assert len(key_output) >= 22  # base64长度


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


def test_make_nonce():
    """测试生成nonce功能"""
    runner = CliRunner()
    result = runner.invoke(main.make_nonce, ["--name", "test", "--base", "command"])
    assert result.exit_code == 0
    assert "Nonce:" in result.output
    # 验证nonce非空
    nonce = result.output.split("Nonce: ")[1].strip()
    assert nonce
    # 验证nonce长度为10
    assert len(nonce) == 10

    # 测试相同输入产生相同的nonce
    result2 = runner.invoke(main.make_nonce, ["--name", "test", "--base", "command"])
    nonce2 = result2.output.split("Nonce: ")[1].strip()
    assert nonce == nonce2

    # 测试不同输入产生不同的nonce
    result3 = runner.invoke(main.make_nonce, ["--name", "different", "--base", "command"])
    nonce3 = result3.output.split("Nonce: ")[1].strip()
    assert nonce != nonce3


def test_generate_ex(tmp_path):
    """测试生成加密的EX文件功能"""
    runner = CliRunner()
    key = base64.b64encode(os.urandom(32)).decode()
    nonce = "test_nonce"
    output_file = str(tmp_path / "test.ex")
    # 使用当前时间加一天作为过期时间，避免过期问题
    expire_timestamp = int(time.time() + 86400)
    meta = f'{{"expire": {expire_timestamp}}}'
    payload = '{"key1": "value1", "key2": "value2"}'

    result = runner.invoke(
        main.generate_ex,
        [
            "-k",
            key,
            "-n",
            nonce,
            "-o",
            output_file,
            "-m",
            meta,
            "-p",
            payload,
        ],
    )

    assert result.exit_code == 0
    assert f"Encrypted EX file saved to {output_file}" in result.output
    assert os.path.exists(output_file)

    # 验证文件内容非空
    with open(output_file) as f:
        content = f.read()
        assert content

    # 验证可以通过decrypt_ex解密
    from exep_tools.crypto import Cipher
    from exep_tools.ex import decrypt_ex

    cipher = Cipher(base64_key=key, str_nonce=nonce)
    ex = decrypt_ex(content, cipher)

    # 验证payload内容
    assert ex.payload["key1"] == "value1"
    assert ex.payload["key2"] == "value2"

    # 验证meta内容
    assert ex.meta["expire"] == expire_timestamp


def test_generate_exep(tmp_path):
    """测试生成加密的EXEP文件功能"""
    runner = CliRunner()
    key = base64.b64encode(os.urandom(32)).decode()
    nonce = "test_nonce"
    output_file = str(tmp_path / "test.exep")
    name = "test_exep"
    expire = int(time.time() + 86400)  # 当前时间戳+1天
    url = "https://example.com/api"

    result = runner.invoke(
        main.generate_exep,
        [
            "-k",
            key,
            "-n",
            nonce,
            "-o",
            output_file,
            "-N",
            name,
            "-e",
            str(expire),
            "-u",
            url,
            "--request-header",
            "Content-Type:application/json",
            "--query",
            "param1:value1",
            "--response-header",
            "Content-Type",
        ],
    )

    assert result.exit_code == 0
    assert f"已加密的 EXEP 文件已保存到 {output_file}" in result.output
    assert "配置摘要:" in result.output
    assert f"  名称: {name}" in result.output
    assert f"  URL: {url}" in result.output
    assert os.path.exists(output_file)

    # 验证文件内容非空
    with open(output_file) as f:
        content = f.read()
        assert content

    # 验证可以通过decrypt_ex解密
    from exep_tools.crypto import Cipher
    from exep_tools.ex import decrypt_ex

    cipher = Cipher(base64_key=key, str_nonce=nonce)
    exep = decrypt_ex(content, cipher)

    # 验证payload内容
    assert exep.payload["url"] == url
    assert exep.payload["request_headers"]["Content-Type"] == "application/json"
    assert exep.payload["queries"]["param1"] == "value1"
    assert "Content-Type" in exep.payload["response_headers"]

    # 验证meta内容
    assert exep.meta["expire"] == expire
    assert exep.meta["name"] == name


def test_invalid_request_header_format():
    """测试无效的请求头格式处理"""
    runner = CliRunner()
    key = base64.b64encode(os.urandom(32)).decode()
    nonce = "test_nonce"

    # 使用无效格式的请求头
    result = runner.invoke(
        main.generate_exep,
        [
            "-k",
            key,
            "-n",
            nonce,
            "-o",
            "output.exep",
            "-N",
            "test",
            "-u",
            "https://example.com",
            "--request-header",
            "invalid-format",  # 没有冒号分隔
        ],
    )

    # 应该显示警告但不会失败
    assert result.exit_code == 0
    assert "警告: 忽略无效的请求头格式 'invalid-format'，应为 '名称:值'" in result.output


def test_invalid_query_format():
    """测试无效的查询参数格式处理"""
    runner = CliRunner()
    key = base64.b64encode(os.urandom(32)).decode()
    nonce = "test_nonce"

    # 使用无效格式的查询参数
    result = runner.invoke(
        main.generate_exep,
        [
            "-k",
            key,
            "-n",
            nonce,
            "-o",
            "output.exep",
            "-N",
            "test",
            "-u",
            "https://example.com",
            "--query",
            "invalid-format",  # 没有冒号分隔
        ],
    )

    # 应该显示警告但不会失败
    assert result.exit_code == 0
    assert "警告: 忽略无效的查询参数格式 'invalid-format'，应为 '名称:值'" in result.output
