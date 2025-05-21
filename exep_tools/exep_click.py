import os
from typing import Any, Optional, Callable

import click

from exep_tools.crypto import Cipher, generate_nonce
from exep_tools.ex import EXLoader


class ExDelegator:
    def __getattr__(self, item: str) -> Callable[..., Optional[Any]]:
        def wrapper(*args: Any, **kwargs: Any) -> Optional[Any]:
            ctx = click.get_current_context()
            if not ctx.obj:
                return None

            return ctx.obj.get(item, None)

        return wrapper


DELEGATOR = ExDelegator()


class ExOption(click.Option):
    def get_default(self, ctx: click.Context, *args: Any, **kwargs: Any) -> Any:
        default = super().get_default(ctx, *args, **kwargs)
        if default is not None:
            return default

        if not ctx.obj:
            return None

        return ctx.obj.get(self.name, None)


class ExGroup(click.Group):
    def __init__(self, loader_key: str = "", *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.__loader_key = loader_key

    def make_context(
        self,
        info_name: str | None,
        args: list[str],
        parent=None,
        **extra,
    ) -> "click.Context":
        ctx = super().make_context(info_name, args, parent, **extra)
        if not self.__loader_key:
            return ctx

        exep = os.getenv("EXEP")
        if not exep:
            return ctx

        nonce = generate_nonce(os.getenv("EXLN", ""), ctx.info_name)
        cipher = Cipher(rot13_key=self.__loader_key, str_nonce=nonce)
        loader = EXLoader(cipher=cipher)
        ex = loader.load(exep_content=exep)
        ctx.obj = ex.payload

        return ctx
