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

    def __enter__(self):
        """实现上下文管理器协议"""
        if hasattr(self.__ctx, "__enter__"):
            self.__ctx.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """实现上下文管理器协议"""
        if hasattr(self.__ctx, "__exit__"):
            return self.__ctx.__exit__(exc_type, exc_val, exc_tb)
        return False

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

        cipher = Cipher(rot13_key=self.loader_key, str_nonce=info_name)
        loader = EXLoader(cipher=cipher)
        ex = loader.load(exep_content=exep)

        return ContextWrapper(ctx, ex)
