import base64
import codecs
import json
from datetime import UTC, datetime

import click
from Crypto.Random import get_random_bytes

from exep_tools.crypto import Cipher
from exep_tools.ex import EX, EXLoader, excrypt_ex

now = datetime.now(UTC)


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
    name: str,
    output: str,
    meta: str,
    payload: str,
):
    """
    生成加密后的 EX 文件。
    """
    cipher = Cipher(base64_key=key, str_nonce=name)

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


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for decrypting")
@click.option(
    "-n",
    "--nonce",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce encryption",
)
@click.option("-e", "--exep", prompt="EXEP content", envvar="EXEP", help="EXEP content")
def validate_exep(key: str, nonce: str, exep: str) -> None:
    """
    验证 EXEP 文件内容是否有效。
    """
    try:
        cipher = Cipher(base64_key=key, str_nonce=nonce)
        loader = EXLoader(cipher=cipher)
        ex = loader.load_from_exep(exep)
    except Exception as e:
        click.echo(f"验证 EXEP 文件失败: {e}", err=True)
        exit(1)

    click.echo(f"EXEP 验证成功，meta 个数: {len(ex.meta)}， payload 个数: {len(ex.payload)}")


if __name__ == "__main__":
    cli()
