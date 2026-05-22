from setuptools import setup, Extension
from Cython.Build import cythonize

setup(
    ext_modules=cythonize(
        Extension(
            "src.core.frontier._state_cython",
            sources=["src/core/frontier/_state_cython.pyx"],
        ),
        compiler_directives={"language_level": "3"},
    )
)
