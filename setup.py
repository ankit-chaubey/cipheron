# cipheron — ARM-CE / AES-NI accelerated Telegram crypto via OpenSSL EVP
# Copyright (c) 2024-Present Ankit Chaubey <ankitchaubey.dev@gmail.com>
# GitHub: https://github.com/ankit-chaubey/cipheron
# License: MIT — see LICENSE file for details

from setuptools import setup, Extension

ext = Extension(
    "cipheron._cipheron",
    sources=["cipheron/_cipheron.c"],
    extra_compile_args=["-O3", "-march=native", "-ffast-math"],
    libraries=["dl"],
)

setup(
    name="cipheron",
    version="0.1.0",
    author="Ankit Chaubey",
    author_email="ankitchaubey.dev@gmail.com",
    url="https://github.com/ankit-chaubey/cipheron",
    license="MIT",
    packages=["cipheron"],
    ext_modules=[ext],
)
