import base64
import codecs
import json
from dataclasses import asdict
from datetime import datetime, timedelta

import click
from Crypto.Random import get_random_bytes

from exep_tools.crypto import Cipher
from exep_tools.env import Magic
from exep_tools.ex import EXLoader


@click.group()
@click.pass_context
def cli(ctx: click.Context) -> None:
    pass


@cli.command()
@click.option("--length", default=32, help="Length of the generated key")
def generate_key(length: int) -> None:
    """
    生成指定长度的 base64 加密密钥，并输出。
    """
    key_bytes = get_random_bytes(length)
    key = base64.b64encode(key_bytes).decode()

    click.echo(f"Generated key: {key}")
    click.echo(f"Key for build: {codecs.encode(key, 'rot13')}")


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for encrypting")
@click.option("-d", "--data", prompt="Data", help="Data to encrypt")
@click.option(
    "-n",
    "--nonce",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for AES encryption (optional)",
)
def encrypt_data(key: str, data: str, nonce: str) -> None:
    """
    使用指定密钥和 nonce 对明文数据进行加密，输出 base64 编码的密文。
    """
    cipher = Cipher(base64_key=key, str_nonce=nonce)
    encrypted = cipher.encrypt_base64(data.encode("utf-8"))
    click.echo(f"Encrypting data: {encrypted.decode()}")


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for decrypting")
@click.option("-d", "--data", prompt="Data", help="Data to decrypt")
@click.option(
    "-n",
    "--nonce",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for AES encryption (optional)",
)
def decrypt_data(key: str, data: str, nonce: str) -> None:
    """
    使用指定密钥和 nonce 对 base64 编码的密文进行解密，输出明文数据。
    """
    cipher = Cipher(base64_key=key, str_nonce=nonce)
    decrypted = cipher.decrypt_base64(data)
    click.echo(f"Decrypting data: {decrypted.decode()}")


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for decrypting")
@click.option(
    "-i", "--input-file", prompt="Input file", type=click.Path(exists=True), help="Path to the encrypted file"
)
@click.option("-o", "--output", prompt="Output file", type=click.Path(), help="Path to save the decrypted file")
@click.option(
    "-n",
    "--nonce",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for AES encryption (optional)",
)
def encrypt_file(key: str, input_file: str, output: str, nonce: str) -> None:
    """
    使用指定密钥和 nonce 对输入文件内容进行加密，结果保存为 base64 编码的密文文件。
    """
    with open(input_file, encoding="utf-8") as f:
        plaintext = f.read()

    cipher = Cipher(base64_key=key, str_nonce=nonce)
    encrypted = cipher.encrypt_base64(plaintext.encode("utf-8"))

    with open(output, "wb") as f:
        f.write(encrypted)

    click.echo(f"Encrypted file saved to {output}")


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for decrypting")
@click.option(
    "-i", "--input-file", prompt="Input file", type=click.Path(exists=True), help="Path to the encrypted file"
)
@click.option("-o", "--output", prompt="Output file", type=click.Path(), help="Path to save the decrypted file")
@click.option(
    "-n",
    "--nonce",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for AES encryption (optional)",
)
def decrypt_file(key: str, input_file: str, output: str, nonce: str) -> None:
    """
    使用指定密钥和 nonce 对加密的文件进行解密，输出为明文文件。
    """
    with open(input_file, "rb") as f:
        encrypted = f.read()

    cipher = Cipher(base64_key=key, str_nonce=nonce)
    # encrypted 需先 base64 解码为 str
    plaintext = cipher.decrypt_base64(encrypted.decode("utf-8"))

    with open(output, "wb") as f:
        f.write(plaintext)

    click.echo(f"Decrypted file saved to {output}")


# Magic结构: access_token, base_url, until_ts, ref_name, remote_file, local_file, allow_commands, disallow_commands, environments
@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for decrypting")
@click.option(
    "-n",
    "--name",
    prompt="Name",
    envvar="EXLN",
    help="Name for the entry",
)
@click.option("-o", "--output", prompt="Output file", help="Path to save the encrypted .exep file")
@click.option(
    "--access-token",
    prompt="Access token",
    envvar="EXEP_GITLAB_TOKEN",
    help="GitLab access token",
)
@click.option("--base-url", prompt="Base URL", envvar="EXEP_GITLAB_URL", help="GitLab base URL")
@click.option(
    "--expire-days",
    prompt="Expire days",
    type=int,
    envvar="EXEP_filePIRE_DAYS",
    help="Number of days until expiration",
)
@click.option(
    "--ref-name",
    prompt="Ref name",
    default="main",
    envvar="EXEP_REF_NAME",
    help="GitLab ref name",
)
@click.option("--remote-file", default=".ex", envvar="EXEP_REMOTE_FILE", help="Remote file name")
@click.option("--local-file", default=".ex", envvar="EXEP_LOCAL_FILE", help="Local file name")
@click.option(
    "--allow-command",
    multiple=True,
    help="Allowed command, can be used multiple times",
)
@click.option(
    "--disallow-command",
    multiple=True,
    help="Disallowed command, can be used multiple times",
)
@click.option(
    "--environment",
    multiple=True,
    help="Environment variable in KEY=VALUE format, can be used multiple times",
)
@click.pass_context
def generate_exep(
    ctx,
    key,
    name,
    output,
    access_token,
    base_url,
    expire_days,
    ref_name,
    remote_file,
    local_file,
    allow_command,
    disallow_command,
    environment,
):
    """
    生成加密后的 magic 文件。
    """
    # 处理 allow/disallow_commands
    allow_commands = list(allow_command) if allow_command else None
    disallow_commands = list(disallow_command) if disallow_command else None
    # 处理 environments
    env_dict = None
    if environment:
        env_dict = {}
        for item in environment:
            if "=" in item:
                k, v = item.split("=", 1)
                env_dict[k] = v
    magic = Magic(
        access_token=access_token,
        base_url=base_url,
        until_ts=int((datetime.now() + timedelta(days=expire_days)).timestamp()),
        ref_name=ref_name,
        remote_file=remote_file,
        local_file=local_file,
        allow_commands=allow_commands,
        disallow_commands=disallow_commands,
        environments=env_dict,
    )

    cipher = Cipher(base64_key=key, str_nonce=name)
    encrypted_magic = cipher.encrypt_base64(json.dumps(asdict(magic)).encode())

    with open(output, "wb") as f:
        f.write(encrypted_magic)

    click.echo(f"Encrypted magic saved to {output}")


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for decrypting")
@click.option(
    "-n",
    "--nonce",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for AES encryption (optional)",
)
@click.option("-e", "--exep-file", prompt="EXEP file", type=click.Path(exists=True), help="Path to the EXEP file")
@click.option("-j", "--json-content", prompt="JSON content", help="Path to the JSON content")
def merge_exep(key: str, nonce: str, exep_file: str, json_content: str) -> None:
    """
    Merge the EXEP file with the JSON content.
    """
    cipher = Cipher(base64_key=key, str_nonce=nonce)
    with open(exep_file, "rb") as f:
        encrypted = f.read()

    decrypted = cipher.decrypt_base64(encrypted.decode())
    magic = json.loads(decrypted)

    new_magic = json.loads(json_content)
    for key, value in new_magic.items():
        if key in magic:
            magic[key] = value

    with open(exep_file, "wb") as f:
        f.write(cipher.encrypt_base64(json.dumps(magic).encode()))


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for encrypting")
@click.option(
    "-n",
    "--name",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for AES encryption",
)
@click.option("-o", "--output", prompt="Output file", type=click.Path(), help="Path to save the EX file")
@click.option(
    "--expire-days",
    default=30,
    help="Days until the EX expires",
)
@click.option("-p", "--payload", prompt="Payload JSON", help="JSON payload for the EX")
def create_ex(key: str, name: str, output: str, expire_days: int, payload: str) -> None:
    """
    创建一个新的 EX 文件，包含指定的 payload 和过期时间。
    """
    try:
        # 解析 payload
        payload_dict = json.loads(payload)

        # 创建 EX 数据结构
        ex_data = {
            "meta": {"expire": int((datetime.now() + timedelta(days=expire_days)).timestamp())},
            "payload": payload_dict,
        }

        # 加密数据
        cipher = Cipher(base64_key=key, str_nonce=name)
        encrypted = cipher.encrypt_base64(json.dumps(ex_data).encode())

        # 保存到文件
        with open(output, "wb") as f:
            f.write(encrypted)

        click.echo(f"成功创建 EX 文件: {output}")
        click.echo(f"过期时间: {datetime.fromtimestamp(ex_data['meta']['expire'])}")
    except Exception as e:
        click.echo(f"创建 EX 文件失败: {e}", err=True)
        exit(1)


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for decrypting")
@click.option(
    "-n",
    "--name",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for AES encryption",
)
@click.option("-f", "--file", prompt="EX file", type=click.Path(exists=True), help="Path to the EX file")
def validate_ex(key: str, name: str, file: str) -> None:
    """
    验证 EX 文件是否有效（未过期）并显示内容。
    """
    try:
        cipher = Cipher(base64_key=key, str_nonce=name)

        # 读取文件
        with open(file, "rb") as f:
            encrypted = f.read().decode()

        # 解密内容
        decrypted = cipher.decrypt_base64(encrypted).decode()
        ex_data = json.loads(decrypted)

        # 检查格式
        if "meta" not in ex_data or "payload" not in ex_data:
            click.echo("无效的 EX 格式: 缺少 meta 或 payload 字段", err=True)
            exit(1)

        # 检查过期时间
        expire = ex_data["meta"].get("expire", 0)
        if not expire:
            click.echo("无效的 EX 格式: 缺少过期时间", err=True)
            exit(1)

        current_time = int(datetime.now().timestamp())
        expire_datetime = datetime.fromtimestamp(expire)

        # 显示内容
        click.echo(f"EX 内容: {json.dumps(ex_data, indent=2)}")
        click.echo(f"过期时间: {expire_datetime}")

        # 检查是否过期
        if current_time >= expire:
            click.echo("EX 已过期", err=True)
            exit(1)
        else:
            days_remaining = (expire_datetime - datetime.now()).days
            click.echo(f"EX 有效,剩余 {days_remaining} 天")

    except Exception as e:
        click.echo(f"验证 EX 文件失败: {e}", err=True)
        exit(1)


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for encrypting")
@click.option(
    "-n",
    "--name",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for AES encryption",
)
@click.option("-o", "--output", prompt="Output file", type=click.Path(), help="Path to save the EXEP file")
@click.option(
    "--expire-days",
    default=90,
    help="Days until the EXEP expires",
)
@click.option("-u", "--url", prompt="EX URL", help="URL to fetch the EX")
@click.option("--header", multiple=True, help="Request headers in format 'key:value'")
@click.option("--query", multiple=True, help="Query parameters in format 'key:value'")
@click.option("--require-header", multiple=True, help="Required response headers")
def create_exep(key: str, name: str, output: str, expire_days: int, url: str, header, query, require_header) -> None:
    """
    创建一个 EXEP 文件，用于后续获取 EX。
    """
    try:
        # 构建请求头
        headers = {}
        for h in header:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()

        # 构建查询参数
        queries = {}
        for q in query:
            if ":" in q:
                k, v = q.split(":", 1)
                queries[k.strip()] = v.strip()

        # 创建 EXEP 数据结构
        exep_data = {
            "meta": {"expire": int((datetime.now() + timedelta(days=expire_days)).timestamp())},
            "payload": {
                "url": url,
                "request_headers": headers,
                "queries": queries,
                "response_headers": list(require_header),
            },
        }

        # 加密数据
        cipher = Cipher(base64_key=key, str_nonce=name)
        encrypted = cipher.encrypt_base64(json.dumps(exep_data).encode())

        # 保存到文件
        with open(output, "wb") as f:
            f.write(encrypted)

        click.echo(f"成功创建 EXEP 文件: {output}")
        click.echo(f"过期时间: {datetime.fromtimestamp(exep_data['meta']['expire'])}")
    except Exception as e:
        click.echo(f"创建 EXEP 文件失败: {e}", err=True)
        exit(1)


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for decrypting")
@click.option(
    "-n",
    "--name",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for AES encryption",
)
@click.option("-e", "--exep", prompt="EXEP file", type=click.Path(exists=True), help="Path to the EXEP file")
def fetch_ex(key: str, name: str, exep: str) -> None:
    """
    通过 EXEP 获取 EX，验证并存储到本地。
    """
    try:
        cipher = Cipher(base64_key=key, str_nonce=name)

        # 读取 EXEP 文件
        with open(exep, "rb") as f:
            exep_content = f.read().decode()

        # 创建 EXLoader 并加载 EX
        loader = EXLoader(cipher)
        ex = loader.load_from_exep(exep_content)

        click.echo("成功获取并验证 EX")
        click.echo(f"过期时间: {datetime.fromtimestamp(ex.expire)}")
        click.echo(f"Payload: {json.dumps(ex.payload, indent=2)}")

    except Exception as e:
        click.echo(f"获取 EX 失败: {e}", err=True)
        exit(1)


if __name__ == "__main__":
    cli()
