import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from tempfile import TemporaryDirectory

import click

from exep_tools import ClickGroup, ClickOption, D
from exep_tools import main as ex_main

key, loader_key = ex_main.generate_key.callback(32)
name = "testing"

port = 9090


@click.group(cls=ClickGroup, loader_key=loader_key)
@click.pass_context
def cli(ctx: click.Context):
    """EXEP 命令行工具示例"""
    pass


@cli.command()
@click.option("--name", cls=ClickOption, help="Name")
@click.option("--greeting", default=D.greeting, help="Greeting")
def check(name: str, greeting: str):
    """检查服务是否正常工作"""

    if greeting != "hello":
        raise click.BadParameter("Greeting must be 'hello'")

    if name != "world":
        raise click.BadParameter("Name must be 'world'")

    print(f"{greeting}, {name}!")


class ExHandler(BaseHTTPRequestHandler):
    ex: bytes

    def do_GET(self):
        """处理 GET 请求"""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(self.ex)


def main():
    """主函数"""

    server = HTTPServer(("localhost", 9090), ExHandler)
    print("Starting server on port 9090...")
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    print("Server started.")

    with TemporaryDirectory() as temp_dir:
        nonce = ex_main.make_nonce.callback(name=name, base="click-command.py")
        expire = int(time.time() + 3600)
        ex = ex_main.generate_ex.callback(
            key=key,
            nonce=nonce,
            output=os.path.join(temp_dir, "ex"),
            meta=f'{{"expire": {expire}}}',
            payload='{"name": "world", "greeting": "hello"}',
        )
        ExHandler.ex = ex.encode("utf-8")

        exep = ex_main.generate_exep.callback(
            key=key,
            nonce=nonce,
            output=os.path.join(temp_dir, "exep"),
            name=name,
            expire=expire,
            url="http://localhost:9090",
            request_header=(),
            query=(),
            response_header=(),
        )
        os.environ["EXEP"] = exep
        os.environ["EXLN"] = "testing"

    time.sleep(1)  # 等待服务器启动

    cli()


if __name__ == "__main__":
    main()
