import base64
import codecs
import json
from datetime import UTC, datetime

import click
from Crypto.Random import get_random_bytes

from exep_tools.crypto import Cipher, generate_nonce
from exep_tools.ex import EX, EXEP, excrypt_ex

now = datetime.now(UTC)


@click.group()
@click.pass_context
def cli(ctx: click.Context) -> None:
    pass


@cli.command()
@click.option("--length", default=32, help="Length of the generated key")
def generate_key(length: int) -> tuple[str, str]:
    """
    生成指定长度的 base64 加密密钥，并输出。
    """
    key_bytes = get_random_bytes(length)
    key = base64.b64encode(key_bytes).decode()
    loader_key = codecs.encode(key, "rot13")

    click.echo(f"EXK: {key}")
    click.echo(f"EXLK: {loader_key}")

    return key, loader_key


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXK", help="Key for encrypting")
@click.option("-d", "--data", prompt="Data", help="Data to encrypt")
@click.option(
    "-n",
    "--nonce",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for AES encryption (optional)",
)
@click.option(
    "-q",
    "--quiet",
    is_flag=True,
    help="只输出核心内容，不加任何描述和格式",
)
def encrypt_data(key: str, data: str, nonce: str, quiet: bool = False) -> str:
    """
    使用指定密钥和 nonce 对明文数据进行加密，输出 base64 编码的密文。
    """
    cipher = Cipher(base64_key=key, str_nonce=nonce)
    encrypted = cipher.encrypt_base64(data.encode()).decode()
    if quiet:
        click.echo(encrypted)
    else:
        click.echo(f"Encrypting data: {encrypted}")
    return encrypted


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXK", help="Key for decrypting")
@click.option("-d", "--data", prompt="Data", help="Data to decrypt")
@click.option(
    "-n",
    "--nonce",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for AES encryption (optional)",
)
@click.option(
    "-q",
    "--quiet",
    is_flag=True,
    help="只输出核心内容，不加任何描述和格式",
)
def decrypt_data(key: str, data: str, nonce: str, quiet: bool = False) -> str:
    """
    使用指定密钥和 nonce 对 base64 编码的密文进行解密，输出明文数据。
    """
    cipher = Cipher(base64_key=key, str_nonce=nonce)
    decrypted = cipher.decrypt_base64(data).decode()
    if quiet:
        click.echo(decrypted)
    else:
        click.echo(f"Decrypting data: {decrypted}")
    return decrypted


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXK", help="Key for decrypting")
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
@click.option("-k", "--key", prompt="Key", envvar="EXK", help="Key for decrypting")
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
@click.option("-k", "--key", prompt="Key", envvar="EXK", help="Key for decrypting")
@click.option(
    "-n",
    "--nonce",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for the entry",
)
@click.option("-o", "--output", prompt="Output file", help="Path to save the encrypted .ex file")
@click.option(
    "-m",
    "--meta",
    default=f'{{"expire": {int(now.timestamp() + 86400)}}}',
    help="Meta data in JSON format",
)
@click.option(
    "-p",
    "--payload",
    prompt="Payload data",
    help="Payload data in JSON format",
)
def generate_ex(
    key: str,
    nonce: str,
    output: str,
    meta: str,
    payload: str,
):
    """
    生成加密后的 EX 文件。
    """
    cipher = Cipher(base64_key=key, str_nonce=nonce)

    # 创建 EX 对象
    ex = EX(
        meta=json.loads(meta),
        payload=json.loads(payload),
    )

    # 使用 excrypt_ex 函数加密 EX 对象
    encrypted_ex = excrypt_ex(ex, cipher)

    with open(output, "w") as f:
        f.write(encrypted_ex)

    click.echo(f"Encrypted EX file saved to {output}")
    return encrypted_ex


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXK", help="Key for decrypting")
@click.option(
    "-n",
    "--nonce",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for the entry",
)
@click.option("-o", "--output", prompt="Output file", help="Path to save the encrypted .ex file")
@click.option(
    "-N",
    "--name",
    prompt="Name",
    help="Name for the entry",
)
@click.option(
    "-e",
    "--expire",
    prompt="Expire time",
    type=int,
    default=f"{int(now.timestamp() + 86400)}",
    help="Expire time for the entry",
)
@click.option(
    "-u",
    "--url",
    prompt="URL",
    help="远程请求的URL地址",
)
@click.option(
    "--request-header",
    multiple=True,
    help="HTTP请求头，格式为'名称:值'，可多次指定",
)
@click.option(
    "--query",
    multiple=True,
    help="URL查询参数，格式为'名称:值'，可多次指定",
)
@click.option(
    "--response-header",
    multiple=True,
    help="需要验证的响应头名称，可多次指定",
)
def generate_exep(
    key: str,
    nonce: str,
    output: str,
    name: str,
    expire: int,
    url: str,
    request_header: tuple,
    query: tuple,
    response_header: tuple,
):
    """
    生成加密后的 EXEP 文件。

    EXEP包含有关远程请求获取EX的配置信息，包括URL、请求头、查询参数和响应头验证等。
    """
    # 解析请求头
    request_headers = {}
    for h in request_header:
        try:
            k, v = h.split(":", 1)
            request_headers[k.strip()] = v.strip()
        except ValueError:
            click.echo(f"警告: 忽略无效的请求头格式 '{h}'，应为 '名称:值'")

    # 解析查询参数
    queries = {}
    for q in query:
        try:
            k, v = q.split(":", 1)
            queries[k.strip()] = v.strip()
        except ValueError:
            click.echo(f"警告: 忽略无效的查询参数格式 '{q}'，应为 '名称:值'")

    # 解析响应头验证列表
    response_headers = [h.strip() for h in response_header]

    cipher = Cipher(base64_key=key, str_nonce=nonce)

    # 创建 EXEP 对象
    exep = EXEP(
        meta={
            "expire": expire,
            "name": name,
        },
        payload={
            "url": url,
            "request_headers": request_headers,
            "queries": queries,
            "response_headers": response_headers,
        },
    )

    # 使用 excrypt_ex 函数加密 EXEP 对象
    encrypted_exep = excrypt_ex(exep, cipher)

    with open(output, "w") as f:
        f.write(encrypted_exep)

    # 输出摘要
    click.echo(f"已加密的 EXEP 文件已保存到 {output}")
    click.echo("配置摘要:")
    click.echo(f"  名称: {name}")
    click.echo(f"  过期时间: {datetime.fromtimestamp(expire, UTC)}")
    click.echo(f"  URL: {url}")
    if request_headers:
        click.echo(f"  请求头: {len(request_headers)}个")
    if queries:
        click.echo(f"  查询参数: {len(queries)}个")
    if response_headers:
        click.echo(f"  响应头验证: {', '.join(response_headers)}")

    return encrypted_exep


@cli.command()
@click.option("-n", "--name", prompt="Name", envvar="EXLN", help="Name for the entry")
@click.option("-b", "--base", prompt="Base Name", envvar="EXB", help="Base name for the entry")
def make_nonce(name: str, base: str) -> str:
    """
    生成 nonce 值。
    """
    nonce = generate_nonce(name, base)
    click.echo(f"Nonce: {nonce}")
    return nonce


if __name__ == "__main__":
    cli()
