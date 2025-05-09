import click
from devops_exep.crypto import Cipher


@click.group()
@click.pass_context
def cli(ctx):
    pass


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
    "-n", "--nonce", prompt="Nonce", help="Nonce for AES encryption (optional)"
)
def encrypt_data(key: str, data: str, nonce: str):
    cipher = Cipher(base64_key=key, str_nonce=nonce)
    encrypted = cipher.encrypt_base64(data.encode("utf-8"))
    click.echo(f"Encrypting data: {encrypted.decode()}")


@cli.command()
@click.option("-k", "--key", prompt="Key", help="Key for decrypting .ex")
@click.option("-d", "--data", prompt="Data", help="Data to decrypt")
@click.option(
    "-n", "--nonce", prompt="Nonce", help="Nonce for AES encryption (optional)"
)
def decrypt_data(key: str, data: str, nonce: str):
    cipher = Cipher(base64_key=key, str_nonce=nonce)
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
    "-n", "--nonce", prompt="Nonce", help="Nonce for AES encryption (optional)"
)
def encrypt_ex(key: str, input_file: str, output: str, nonce: str):
    with open(input_file, "rt") as f:
        plaintext = f.read()

    cipher = Cipher(base64_key=key, str_nonce=nonce)
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
    "-n", "--nonce", prompt="Nonce", help="Nonce for AES encryption (optional)"
)
def decrypt_ex(key: str, input_file: str, output: str, nonce: str):
    with open(input_file, "rb") as f:
        encrypted = f.read()

    cipher = Cipher(base64_key=key, str_nonce=nonce)
    plaintext = cipher.decrypt_base64(encrypted)

    with open(output, "wb") as f:
        f.write(plaintext)

    click.echo(f"Decrypted file saved to {output}")


if __name__ == "__main__":
    cli()
