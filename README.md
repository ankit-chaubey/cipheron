<!--
  cipheron — ARM-CE / AES-NI accelerated Telegram crypto via OpenSSL EVP
  Copyright (c) 2024-Present Ankit Chaubey <ankitchaubey.dev@gmail.com>
  GitHub: https://github.com/ankit-chaubey/cipheron
  License: MIT
-->

<div align="center">

# ⚡ cipheron

**ARM-CE / AES-NI accelerated Telegram crypto via OpenSSL EVP**

[![PyPI](https://img.shields.io/pypi/v/cipheron?color=blue&logo=pypi&logoColor=white)](https://pypi.org/project/cipheron/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/pypi/pyversions/cipheron)](https://pypi.org/project/cipheron/)
[![GitHub](https://img.shields.io/badge/GitHub-ankit--chaubey%2Fcipheron-black?logo=github)](https://github.com/ankit-chaubey/cipheron)
[![Stars](https://img.shields.io/github/stars/ankit-chaubey/cipheron?style=social)](https://github.com/ankit-chaubey/cipheron/stargazers)

> Drop-in replacement for `tgcrypto`, `cryptg`, and `cryptogram` — with **5–6× faster IGE** by routing AES through OpenSSL's hardware engine instead of software T-tables.

</div>

---

## 💬 A personal note

I originally built **cipheron** in **2024 for my own personal use** — I was frustrated that Telegram crypto on ARM devices (Termux, Android, Raspberry Pi) was bottlenecked by software AES even though the hardware was perfectly capable of going 5× faster. So I fixed it. 😄

If cipheron helps speed up your bots, userbots, or Telegram clients — **don't forget to ⭐ star the repo, it means a lot!**  
And do check out [**cryptogram**](https://github.com/pyrogram/cryptogram) ([PyPI](https://pypi.org/project/cryptogram/)) — the excellent project that inspired this work. cipheron builds on the same idea and takes it further with full OpenSSL EVP dispatch.

---

## 🧠 Why cipheron exists

Every Telegram message, file chunk, and MTProto packet is encrypted with **AES-256-IGE**. Popular libraries like `tgcrypto` and `cryptogram` implement IGE using `AES_encrypt()` — a software path that bypasses ARM Crypto Extensions and AES-NI entirely.

**cipheron fixes this** by routing all AES operations through OpenSSL's `EVP_CipherUpdate()`, which dispatches to hardware automatically:

```
EVP_CipherUpdate()  →  OpenSSL engine dispatch  →  aes_v8_encrypt (ARM-CE)  →  843 MB/s ✅
AES_encrypt()       →  software T-table path    →  ~130 MB/s  ← tgcrypto / cryptogram stuck here ❌
```

On a device with ARM Crypto Extensions confirmed at **843 MB/s CBC**, cipheron IGE lands at **~600–800 MB/s** — making crypto essentially free and your network the only bottleneck.

---

## 📦 Installation

```bash
pip install cipheron
```

**Termux / Android (ARM):**
```bash
pkg install clang openssl python
pip install cipheron
```

**Verify hardware acceleration:**
```bash
python -c "import cipheron; print(cipheron.get_backend(), '|', cipheron.has_aesni())"
# C/EVP+ARM-CE | True
```

---

## 🔌 Drop-in replacement — Pyrogram & Telethon

### Method 1: `sys.modules` hijack ✅ recommended

Add **two lines before any Pyrogram/Telethon import** — zero other code changes needed:

```python
import sys
import cipheron

# Pyrogram uses tgcrypto internally
sys.modules['tgcrypto'] = cipheron

# Telethon uses cryptg internally
sys.modules['cryptg'] = cipheron

# Now import normally — cipheron handles all crypto transparently ⚡
from pyrogram import Client
# or
from telethon import TelegramClient
```

### Method 2: Direct API (same as tgcrypto)

```python
import cipheron

# IGE-256 — used for every MTProto message & file chunk
encrypted = cipheron.ige256_encrypt(data, key, iv)
decrypted = cipheron.ige256_decrypt(encrypted, key, iv)

# CTR-256 — obfuscated transport layer
out, state = cipheron.ctr256_encrypt(data, key, iv, state)
out, state = cipheron.ctr256_decrypt(data, key, iv, state)

# CBC-256
encrypted = cipheron.cbc256_encrypt(data, key, iv)
decrypted = cipheron.cbc256_decrypt(encrypted, key, iv)

# PQ factorization — Telegram handshake (unique to cipheron!)
p, q = cipheron.factorize_pq_pair(pq_int)

# Runtime detection
print(cipheron.has_aesni())    # True on ARM-CE / AES-NI hardware
print(cipheron.get_backend())  # "C/EVP+ARM-CE"
```

### Method 3: Replace all frameworks at once

```python
import sys, cipheron

for name in ('tgcrypto', 'cryptg', 'cryptogram'):
    sys.modules[name] = cipheron

# Works transparently with any Telegram framework ✅
```

---

## 🚀 Benchmark Results

### ARM Device (Termux / Android) — ARM Crypto Extensions active

```
openssl speed -evp aes-256-cbc → 843 MB/s  ← hardware AES confirmed ✅
843 MB/s = ARM Crypto Extensions are 100% active!

── IGE ENCRYPT (MB/s) ──────────────────────────────────────────────
  Size        tgcrypto    cryptogram    cipheron      speedup
  16 KB         ~130          ~100       ~750 ▲       5.8× 🏆
  256 KB        ~125           ~85       ~680 ▲       5.4× 🏆
  1 MB          ~128           ~90       ~700 ▲       5.5× 🏆
  8 MB          ~130           ~88       ~720 ▲       5.5× 🏆

── CTR ENCRYPT (MB/s) ──────────────────────────────────────────────
  16 KB         ~150          ~800       ~840 ▲       5.6× 🏆
  256 KB        ~148          ~810       ~830 ▲       5.6× 🏆

── CBC ENCRYPT (MB/s) ──────────────────────────────────────────────
  16 KB         ~155          ~820       ~843 ▲       5.4× 🏆

Correctness: IGE ✓ PASS   CTR ✓ PASS   CBC ✓ PASS
```

> **Why 843 MB/s matters:** cipheron routes IGE through the same hardware path as CBC. That's the entire trick — and it makes all the difference.

### x86 Desktop (AES-NI) — Verified benchmark

```
── IGE ENCRYPT (MB/s) ──────────────────────────────────────────────
  Size        tgcrypto    cryptogram    cipheron      speedup
  16 KB          172         102          792 ▲       4.60× 🏆
  256 KB         133          87          353 ▲       2.65× 🏆
  1 MB           140          90          418 ▲       2.99× 🏆
  8 MB           144          90          422 ▲       2.93× 🏆

── CTR ENCRYPT (MB/s) ──────────────────────────────────────────────
  16 KB          153         964 ▲        957 ▲       6.27× 🏆
  256 KB         152         967 ▲        963 ▲       6.33× 🏆

── CBC ENCRYPT (MB/s) ──────────────────────────────────────────────
  16 KB          180         970 ▲        972 ▲       5.39× 🏆

Correctness: IGE ✓ PASS   CTR ✓ PASS
```

### Run your own benchmark

```python
import os, time, cipheron, tgcrypto

KEY = os.urandom(32)
IV  = os.urandom(32)
D   = os.urandom(1024 * 1024)
N   = 100

t = time.perf_counter()
for _ in range(N): cipheron.ige256_encrypt(D, KEY, IV)
print(f'cipheron : {N / (time.perf_counter() - t) * 1024:.0f} MB/s')

t = time.perf_counter()
for _ in range(N): tgcrypto.ige256_encrypt(D, KEY, IV)
print(f'tgcrypto : {N / (time.perf_counter() - t) * 1024:.0f} MB/s')
```

---

## 📊 Real-world impact

| Use case | Mode | cipheron vs tgcrypto |
|---|---|---|
| Telegram file upload / download | IGE | **5–6× faster** on ARM |
| Every MTProto message | IGE | **5–6× faster** |
| Pyrogram obfuscated transport | CTR | **4–6× faster** |
| Telegram CDN file chunks | CTR | **4–6× faster** |
| Bot handling 1000s of msgs/sec | IGE | biggest real-world win |
| Connection handshake | PQ | only cipheron has it built-in |
| Heavy userbot (files + messages) | all modes | **cipheron wins everything** |

> Each Telegram file transfer splits into **512 KB IGE-encrypted chunks**. At ~800 MB/s vs ~130 MB/s, crypto overhead per chunk drops from ~4ms to ~0.6ms — your CPU is essentially free and the network is your only limit.

---

## 📚 API Reference

| Function | Description |
|---|---|
| `ige256_encrypt(data, key, iv)` | AES-256 IGE encrypt |
| `ige256_decrypt(data, key, iv)` | AES-256 IGE decrypt |
| `ctr256_encrypt(data, key, iv, state)` | AES-256 CTR encrypt |
| `ctr256_decrypt(data, key, iv, state)` | AES-256 CTR decrypt |
| `cbc256_encrypt(data, key, iv)` | AES-256 CBC encrypt |
| `cbc256_decrypt(data, key, iv)` | AES-256 CBC decrypt |
| `encrypt_ige(data, key, iv)` | Alias → `ige256_encrypt` |
| `decrypt_ige(data, key, iv)` | Alias → `ige256_decrypt` |
| `factorize_pq_pair(pq)` | RSA PQ factorization (Telegram handshake) |
| `has_aesni()` | `True` if hardware AES is available |
| `get_backend()` | Backend string e.g. `"C/EVP+ARM-CE"` |

---

## 🙏 Credits & Inspiration

- [**cryptogram**](https://github.com/pyrogram/cryptogram) ([PyPI](https://pypi.org/project/cryptogram/)) — the project that started it all. Highly recommended!
- [**tgcrypto**](https://github.com/pyrogram/tgcrypto) — the standard Telegram crypto library for Pyrogram
- [**cryptg**](https://github.com/cher-nov/cryptg) — Telethon's native crypto backend

---

## 👨‍💻 Developed by [Ankit Chaubey](https://github.com/ankit-chaubey)  
📧 ankitchaubey.dev@gmail.com  
🌐 [github.com/ankit-chaubey/cipheron](https://github.com/ankit-chaubey/cipheron)

---

## 📄 License

[MIT](LICENSE) © 2024-Present [Ankit Chaubey](https://github.com/ankit-chaubey/cipheron)

---

<div align="center">

**If cipheron made your Telegram bots or scripts faster — drop a ⭐ star, it genuinely helps!**

</div>
