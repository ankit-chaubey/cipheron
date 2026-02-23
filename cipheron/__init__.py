# cipheron — ARM-CE / AES-NI accelerated Telegram crypto via OpenSSL EVP
# Copyright (c) 2024-Present Ankit Chaubey <ankitchaubey.dev@gmail.com>
# GitHub: https://github.com/ankit-chaubey/cipheron
# License: MIT — see LICENSE file for details
"""
cipheron — ARM-CE / AES-NI accelerated Telegram crypto via OpenSSL EVP

Fixes cryptogram's IGE bottleneck: routes AES block encryption through
EVP_CipherUpdate() instead of AES_encrypt(), activating ARM Crypto
Extensions and AES-NI that OpenSSL's engine dispatch provides.

API: fully compatible with tgcrypto, cryptg, and cryptogram.
"""
from ._cipheron import (
    ige256_encrypt, ige256_decrypt,
    ctr256_encrypt, ctr256_decrypt,
    cbc256_encrypt, cbc256_decrypt,
    encrypt_ige, decrypt_ige,
    factorize_pq_pair,
    has_aesni, get_backend,
)

__version__ = "1.0.0"
__author__ = "Ankit Chaubey"
__email__ = "ankitchaubey.dev@gmail.com"
__license__ = "MIT"
__url__ = "https://github.com/ankit-chaubey/cipheron"

__all__ = [
    "ige256_encrypt", "ige256_decrypt",
    "ctr256_encrypt", "ctr256_decrypt",
    "cbc256_encrypt", "cbc256_decrypt",
    "encrypt_ige", "decrypt_ige",
    "factorize_pq_pair",
    "has_aesni", "get_backend",
]
