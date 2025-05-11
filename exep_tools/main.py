import base64
import codecs

import click
from Crypto.Random import get_random_bytes

from exep_tools.crypto import Cipher


@click.group()
@click.pass_context
def cli(ctx: click.Context) -> None:
    pass


@cli.command()
@click.option("--length", default=32, help="Length of the generated key")
def generate_ex_key(length: int) -> None:
    key_bytes = get_random_bytes(length)
    key = base64.b64encode(key_bytes).decode()

    click.echo(f"Generated key: {key}")
    click.echo(f"Key for build: {codecs.encode(key, 'rot13')}")


@cli.command()
@click.option("-k", "--key", prompt="Key", help="Key for encrypting .ex")
@click.option("-d", "--data", prompt="Data", help="Data to encrypt")
@click.option("-n", "--nonce", prompt="Nonce", help="Nonce for AES encryption (optional)")
def encrypt_data(key: str, data: str, nonce: str) -> None:
    cipher = Cipher(base64_key=key, str_nonce=nonce)
    encrypted = cipher.encrypt_base64(data.encode("utf-8"))
    click.echo(f"Encrypting data: {encrypted.decode()}")


@cli.command()
@click.option("-k", "--key", prompt="Key", help="Key for decrypting .ex")
@click.option("-d", "--data", prompt="Data", help="Data to decrypt")
@click.option("-n", "--nonce", prompt="Nonce", help="Nonce for AES encryption (optional)")
def decrypt_data(key: str, data: str, nonce: str) -> None:
    cipher = Cipher(base64_key=key, str_nonce=nonce)
    decrypted = cipher.decrypt_base64(data)
    click.echo(f"Decrypting data: {decrypted.decode()}")


@cli.command()
@click.option("-k", "--key", prompt="Key", help="Key for decrypting .ex")
@click.option("-i", "--input-file", prompt="Input file", help="Path to the encrypted .ex file")
@click.option("-o", "--output", prompt="Output file", help="Path to save the decrypted .ex file")
@click.option("-n", "--nonce", prompt="Nonce", help="Nonce for AES encryption (optional)")
def encrypt_ex(key: str, input_file: str, output: str, nonce: str) -> None:
    with open(input_file, encoding="utf-8") as f:
        plaintext = f.read()

    cipher = Cipher(base64_key=key, str_nonce=nonce)
    encrypted = cipher.encrypt_base64(plaintext.encode("utf-8"))

    with open(output, "wb") as f:
        f.write(encrypted)

    click.echo(f"Encrypted file saved to {output}")


@cli.command()
@click.option("-k", "--key", prompt="Key", help="Key for decrypting .ex")
@click.option("-i", "--input-file", prompt="Input file", help="Path to the encrypted .ex file")
@click.option("-o", "--output", prompt="Output file", help="Path to save the decrypted .ex file")
@click.option("-n", "--nonce", prompt="Nonce", help="Nonce for AES encryption (optional)")
def decrypt_ex(key: str, input_file: str, output: str, nonce: str) -> None:
    with open(input_file, "rb") as f:
        encrypted = f.read()

    cipher = Cipher(base64_key=key, str_nonce=nonce)
    # encrypted 需先 base64 解码为 str
    plaintext = cipher.decrypt_base64(encrypted.decode("utf-8"))

    with open(output, "wb") as f:
        f.write(plaintext)

    click.echo(f"Decrypted file saved to {output}")


if __name__ == "__main__":
    cli()
