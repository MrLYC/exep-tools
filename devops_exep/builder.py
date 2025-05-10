import os
import logging
import shutil
from dataclasses import dataclass

from Cython.Build.Cythonize import main
import pathlib
from ast_grep_py import SgRoot

logger = logging.getLogger(__name__)


@dataclass
class Builder:
    root_dir: str
    entry_file: str = ""

    def inject_loader_key(self) -> bool:
        loader_key = os.getenv("EXLK")
        if not loader_key:
            return False

        with open(self.entry_file, "r") as file:
            root = SgRoot(file.read(), "python")

        node = root.root()
        hook = node.find(patter="@click.group(cls=ExepCommand)")
        if not hook:
            logger.error("No hook found for ExepCommand")
            return False

        result = node.commit_edits(
            [
                hook.replace(
                    f"@click.group(cls=ExepCommand, loader_key='{loader_key}')",
                )
            ]
        )

        with open(self.entry_file, "w") as file:
            file.write(result)
            file.truncate()

    def build(self):
        self.inject_loader_key()
        main(["-i", self.root_dir])
