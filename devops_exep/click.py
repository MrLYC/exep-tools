from click import Command as BaseCommand
from devops_exep.env import Loader
import os


class Command(BaseCommand):
    def __init__(self, key: str = "", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.key = key
        self.nonce = ""

    def make_context(self, info_name: str, args: list, parent=None):
        self.nonce = info_name
        exep = os.getenv("EXEP")
        if exep:
            Loader(
                key=self.key,
                nonce=self.nonce,
                magic=exep,
            ).load_encrypted_env()

        return super().make_context(info_name, args, parent)
