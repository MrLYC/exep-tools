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

    def make_context(
        self,
        info_name: str | None,
        args: list[str],
        parent=None,
        **extra,
    ) -> "click.Context":
        ctx = super().make_context(info_name, args, parent, **extra)

        exep = os.getenv("EXEP")
        if exep:
            loader = Loader(
                key=self.loader_key,
                name=info_name,
                command=ctx.invoked_subcommand,
                magic=exep,
            )

            loader.load_encrypted_env()

        return ctx
