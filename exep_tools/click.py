import os
from typing import TYPE_CHECKING

from click import Group as BaseGroup

from exep_tools.env import Loader

if TYPE_CHECKING:
    import click


class ExepGroup(BaseGroup):
    def __init__(self, loader_key: str = "", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.loader_key = loader_key
        self.nonce = ""

    def make_context(
        self,
        info_name: str | None,
        args: list[str],
        parent=None,
        **extra,
    ) -> "click.Context":
        self.nonce = info_name or ""
        exep = os.getenv("EXEP")
        if exep:
            Loader(
                key=self.loader_key,
                nonce=self.nonce,
                magic=exep,
            ).load_encrypted_env()

        return super().make_context(info_name, args, parent, **extra)
