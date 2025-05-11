from pathlib import Path
from Cython.Build.Cythonize import main


def build():
    my_path = Path(__file__)
    src_dir = my_path.parent.parent / "exep_tools"

    main(["-i", str(src_dir)])


if __name__ == "__main__":
    build()
