import shutil
import sys

from setuptools import Extension, setup


def has_compiler() -> bool:
    # Defensive check for C compiler availability to avoid aborting builds on systems without compiler tools
    if sys.platform == "win32":
        if shutil.which("cl.exe"):
            return True
        try:
            from distutils.ccompiler import new_compiler

            cc = new_compiler()
            cc.initialize()
            return True
        except Exception:
            return False
    else:
        for compiler in ("gcc", "clang", "cc"):
            if shutil.which(compiler):
                return True
        return False


ext_modules = []
if has_compiler():
    try:
        from Cython.Build import cythonize

        ext_modules = cythonize(
            Extension(
                "src.core.frontier._state_cython",
                sources=["src/core/frontier/_state_cython.pyx"],
            ),
            compiler_directives={"language_level": "3"},
        )
    except Exception:  # noqa: S110
        pass

setup(ext_modules=ext_modules)
