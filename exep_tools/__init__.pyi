from click import Group as ClickGroup

class _DELEGATOR:
    def __getattr__(self, item: str) -> callable: ...

D = _DELEGATOR()

__all__ = ["ClickGroup", "D"]
