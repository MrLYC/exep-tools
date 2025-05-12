import base64
import codecs
import json
from dataclasses import asdict

import click
from Crypto.Random import get_random_bytes

from exep_tools.crypto import Cipher
from exep_tools.env import Magic


@click.group()
@click.pass_context
def cli(ctx: click.Context) -> None:
    pass


@cli.command()
@click.option("--length", default=32, help="Length of the generated key")
def generate_ex_key(length: int) -> None:
    """
    生成指定长度的 base64 加密密钥，并输出。
    用于 .ex 文件的加密。
    """
    key_bytes = get_random_bytes(length)
    key = base64.b64encode(key_bytes).decode()

    click.echo(f"Generated key: {key}")
    click.echo(f"Key for build: {codecs.encode(key, 'rot13')}")


@cli.command()
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for encrypting .ex")
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
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for decrypting .ex")
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
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for decrypting .ex")
@click.option("-i", "--input-file", prompt="Input file", help="Path to the encrypted .ex file")
@click.option("-o", "--output", prompt="Output file", help="Path to save the decrypted .ex file")
@click.option(
    "-n",
    "--nonce",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for AES encryption (optional)",
)
def encrypt_ex(key: str, input_file: str, output: str, nonce: str) -> None:
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
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for decrypting .ex")
@click.option("-i", "--input-file", prompt="Input file", help="Path to the encrypted .ex file")
@click.option("-o", "--output", prompt="Output file", help="Path to save the decrypted .ex file")
@click.option(
    "-n",
    "--nonce",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for AES encryption (optional)",
)
def decrypt_ex(key: str, input_file: str, output: str, nonce: str) -> None:
    """
    使用指定密钥和 nonce 对加密的 .ex 文件进行解密，输出为明文文件。
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
@click.option("-k", "--key", prompt="Key", envvar="EXLK", help="Key for decrypting .ex")
@click.option(
    "-n",
    "--nonce",
    prompt="Nonce",
    envvar="EXLN",
    help="Nonce for AES encryption (optional)",
)
@click.option("-o", "--output", prompt="Output file", help="Path to save the encrypted .exep file")
@click.option(
    "--access-token",
    prompt="Access token",
    envvar="GITLAB_TOKEN",
    help="GitLab access token",
)
@click.option("--base-url", prompt="Base URL", envvar="GITLAB_URL", help="GitLab base URL")
@click.option(
    "--until-ts",
    prompt="Until timestamp",
    type=int,
    envvar="UNTIL_TS",
    help="Until timestamp",
)
@click.option(
    "--ref-name",
    prompt="Ref name",
    default="main",
    envvar="REF_NAME",
    help="GitLab ref name",
)
@click.option("--remote-file", default=".exep", envvar="REMOTE_FILE", help="Remote file name")
@click.option("--local-file", default=".exep", envvar="LOCAL_FILE", help="Local file name")
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
    nonce,
    output,
    access_token,
    base_url,
    until_ts,
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
        until_ts=until_ts,
        ref_name=ref_name,
        remote_file=remote_file,
        local_file=local_file,
        allow_commands=allow_commands,
        disallow_commands=disallow_commands,
        environments=env_dict,
    )

    cipher = Cipher(base64_key=key, str_nonce=nonce)
    encrypted_magic = cipher.encrypt_base64(json.dumps(asdict(magic)).encode())

    with open(output, "wb") as f:
        f.write(encrypted_magic)

    click.echo(f"Encrypted magic saved to {output}")


if __name__ == "__main__":
    cli()
