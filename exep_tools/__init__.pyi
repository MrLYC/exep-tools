from click import Group as ClickGroup
from click import Option as ClickOption
from typing import Any, Callable, Optional

class _D:
    def __getattr__(self, item: str) -> Callable[..., Optional[Any]]: ...

D = _D()

__all__ = ["ClickGroup", "ClickOption", "D"]
