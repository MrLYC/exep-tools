import os
from typing import Any, Optional

import click
from click import Group as BaseGroup

from exep_tools.crypto import Cipher, generate_nonce
from exep_tools.ex import EXLoader


class ExDelegator:
    def __getattr__(self, item: str) -> callable:
        def wrapper(*args: Any, **kwargs: Any) -> Optional[Any]:
            ctx = click.get_current_context()
            if not ctx.obj:
                return None

            return ctx.obj.get(item, None)

        return wrapper


DELEGATOR = ExDelegator()


class ExGroup(BaseGroup):
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
