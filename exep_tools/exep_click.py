import os
from typing import TYPE_CHECKING, Any, Optional

from click import Group as BaseGroup

from exep_tools.crypto import Cipher
from exep_tools.ex import EX, EXLoader

if TYPE_CHECKING:
    import click


class ContextWrapper:
    def __init__(self, ctx: "click.Context", ex: EX) -> None:
        self.__ctx = ctx
        self.__env = ex.payload

    def __getattr__(self, item: str):
        return getattr(self.__ctx, item)

    def lookup_default(self, name: str, call: bool = True) -> Optional[Any]:
        """
        获取上下文中的默认值，如果不存在则返回 None
        """

        value = self.__ctx.lookup_default(name, call)
        if value is not None:
            return value
        elif name in self.__env:
            return self.__env[name]

        return None


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
        if not exep:
            return ctx

        cipher = Cipher(base64_key=self.loader_key, str_nonce=info_name)
        loader = EXLoader(cipher=cipher)
        ex = loader.load()

        return ContextWrapper(ctx, ex)
