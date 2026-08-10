"""Compatibility shim for editable installs with older pip/setuptools."""

from setuptools import setup


setup(
    name="mini-re",
    version="0.5.0",
    py_modules=["mini_re", "advanced", "verifiers", "integration_matrix"],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "mini-re=mini_re:main",
            "mini-re-matrix=integration_matrix:main",
        ]
    },
)
