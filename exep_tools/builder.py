import logging
import os
from dataclasses import dataclass

from ast_grep_py import SgRoot
from Cython.Build.Cythonize import main

logger = logging.getLogger(__name__)


@dataclass
class Builder:
    root_dir: str
    entry_file: str = ""

    def inject_loader_key(self) -> bool:
        loader_key = os.getenv("EXLK")
        if not loader_key:
            return False

        with open(self.entry_file) as file:
            root = SgRoot(file.read(), "python")

        node = root.root()
        hook = node.find(pattern="@click.group(cls=ClickGroup)")
        if not hook:
            logger.error("No hook found for ClickGroup")
            return False

        result = node.commit_edits([
            hook.replace(
                f"@click.group(cls=ClickGroup, loader_key='{loader_key}')",
            )
        ])

        with open(self.entry_file, "w") as file:
            file.write(result)
            file.truncate()

        return True

    def build(self) -> None:
        self.inject_loader_key()
        main(["-i", self.root_dir])
