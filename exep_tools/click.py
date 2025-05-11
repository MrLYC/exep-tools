from click import Command as BaseCommand
from exep_tools.env import Loader
import os


class ExepCommand(BaseCommand):
    def __init__(self, loader_key: str = "", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.loader_key = loader_key
        self.nonce = ""

    def make_context(self, info_name: str, args: list, parent=None):
        self.nonce = info_name
        exep = os.getenv("EXEP")
        if exep:
            Loader(
                key=self.loader_key,
                nonce=self.nonce,
                magic=exep,
            ).load_encrypted_env()

        return super().make_context(info_name, args, parent)
