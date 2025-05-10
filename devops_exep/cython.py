import os
import logging
import shutil
from dataclasses import dataclass

from Cython.Build.Cythonize import main
import pathlib

logger = logging.getLogger(__name__)


@dataclass
class Builder:
    root_dir: str

    def build(self):
        main(["-i", self.root_dir])
