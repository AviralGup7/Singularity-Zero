from Cython.Build import cythonize
from setuptools import Extension, setup

setup(
    ext_modules=cythonize(
        Extension(
            "src.core.frontier._state_cython",
            sources=["src/core/frontier/_state_cython.pyx"],
        ),
        compiler_directives={"language_level": "3"},
    )
)
