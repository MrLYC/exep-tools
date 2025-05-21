from typing import Any, Callable

from click import Group as ClickGroup
from click import Option as ClickOption

class _D:
    def __getattr__(self, item: str) -> Callable[..., Any]: ...

D = _D()

__all__ = ["ClickGroup", "ClickOption", "D"]
