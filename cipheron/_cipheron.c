/*
 * cipheron — ARM-CE / AES-NI accelerated Telegram crypto via OpenSSL EVP
 * Copyright (c) 2024-Present Ankit Chaubey <ankitchaubey.dev@gmail.com>
 * GitHub: https://github.com/ankit-chaubey/cipheron
 * License: MIT — see LICENSE file for details
 */

/*
 * cipheron — ARM/AES-NI accelerated Telegram crypto
 * Beats tgcrypto on IGE by routing through OpenSSL EVP (ARM CE / AES-NI)
 * instead of raw AES_encrypt() which bypasses hardware acceleration.
 *
 * ROOT CAUSE of cryptogram's IGE slowness (from source audit):
 *   cryptogram do_ige() calls G.aes_enc() = AES_encrypt() — a low-level
 *   OpenSSL symbol that does NOT dispatch through the ENGINE layer.
 *   ARM CE / AES-NI is only activated via EVP_CipherUpdate().
 *
 * FIX: Use EVP ECB context (created ONCE per call, reused per block)
 *   EVP ECB → OpenSSL engine dispatch → ARM Crypto Extensions → ~800 MB/s
 *
 * API: fully compatible with tgcrypto AND cryptg AND cryptogram
 *   ige256_encrypt, ige256_decrypt   (tgcrypto / cryptogram style)
 *   ctr256_encrypt, ctr256_decrypt   (tgcrypto / cryptogram style)
 *   cbc256_encrypt, cbc256_decrypt   (tgcrypto / cryptogram style)
 *   encrypt_ige,    decrypt_ige      (cryptg style)
 *   factorize_pq_pair                (cryptg / cryptogram style)
 *   has_aesni()                      (backend info)
 *   get_backend()                    (backend name string)
 */

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ── Platform dlopen ──────────────────────────────────────────────── */
#ifdef _WIN32
# include <windows.h>
# define dl_open(n)  ((void*)LoadLibrary(n))
# define dl_sym(h,n) ((void*)GetProcAddress((HMODULE)(h),(n)))
#else
# include <dlfcn.h>
# include <dirent.h>
# define dl_open(n)  dlopen((n), RTLD_LAZY|RTLD_GLOBAL)
# define dl_sym(h,n) dlsym((h),(n))
#endif

/* ── OpenSSL type declarations ────────────────────────────────────── */
typedef struct { uint32_t rd_key[60]; int rounds; } AES_KEY_T;
typedef void* EVP_CIPHER_CTX;
typedef void* EVP_CIPHER;

typedef int  (*fn_set_enc)    (const unsigned char*, int, AES_KEY_T*);
typedef int  (*fn_set_dec)    (const unsigned char*, int, AES_KEY_T*);
typedef void (*fn_aes_raw)    (const unsigned char*, unsigned char*, const AES_KEY_T*);
typedef EVP_CIPHER_CTX* (*fn_ctx_new)  (void);
typedef void            (*fn_ctx_free) (EVP_CIPHER_CTX*);
typedef int  (*fn_c_init)     (EVP_CIPHER_CTX*, const EVP_CIPHER*, void*,
                               const unsigned char*, const unsigned char*, int);
typedef int  (*fn_c_update)   (EVP_CIPHER_CTX*, unsigned char*, int*,
                               const unsigned char*, int);
typedef int  (*fn_c_final)    (EVP_CIPHER_CTX*, unsigned char*, int*);
typedef int  (*fn_c_pad)      (EVP_CIPHER_CTX*, int);
typedef const EVP_CIPHER* (*fn_cipher_fn)(void);

static struct {
    void          *lib;
    fn_set_enc     set_enc;
    fn_set_dec     set_dec;
    fn_aes_raw     aes_enc_raw;   /* AES_encrypt — fallback only */
    fn_aes_raw     aes_dec_raw;   /* AES_decrypt — fallback only */
    fn_ctx_new     ctx_new;
    fn_ctx_free    ctx_free;
    fn_c_init      c_init;
    fn_c_update    c_update;
    fn_c_final     c_final;
    fn_c_pad       c_pad;
    fn_cipher_fn   evp_ecb;       /* EVP_aes_256_ecb */
    fn_cipher_fn   evp_cbc;       /* EVP_aes_256_cbc */
    int            ok;            /* 1=loaded, -1=failed */
    int            backend;       /* 0=T-table 1=ARM-CE 2=AES-NI */
} G;

/* ── Load OpenSSL ─────────────────────────────────────────────────── */
static void ssl_load(void) {
    if (G.ok) return;
#ifdef __APPLE__
    G.ok = -1; return;
#endif
    /* Try process-global first (already loaded by Python's ssl module) */
    void *h = dlopen(NULL, RTLD_LAZY);
    if (h && dl_sym(h, "EVP_aes_256_ecb")) { G.lib = h; goto syms; }

    /* Then try system library names */
    static const char *libs[] = {
        "libcrypto.so.3","libcrypto.so.1.1","libcrypto.so.1.0.0",
        "libcrypto.so","libssl.so.3","libssl.so.1.1","libssl.so",
        /* Termux path */
        "/data/data/com.termux/files/usr/lib/libcrypto.so.3",
        "/data/data/com.termux/files/usr/lib/libcrypto.so.1.1",
        "/data/data/com.termux/files/usr/lib/libcrypto.so",
        "/data/data/com.termux/files/usr/lib/libssl.so.3",
        "/data/data/com.termux/files/usr/lib/libssl.so",
        "/system/lib64/libcrypto.so",
        "/system/lib/libcrypto.so",
        NULL
    };
    for (int i = 0; libs[i]; i++) {
        G.lib = dl_open(libs[i]);
        if (G.lib) break;
    }
    if (!G.lib) { G.ok = -1; return; }
syms:;
#define LD(f,sym,T) G.f=(T)dl_sym(G.lib,sym); if(!G.f){G.ok=-1;return;}
    LD(set_enc,    "AES_set_encrypt_key", fn_set_enc)
    LD(set_dec,    "AES_set_decrypt_key", fn_set_dec)
    LD(aes_enc_raw,"AES_encrypt",         fn_aes_raw)
    LD(aes_dec_raw,"AES_decrypt",         fn_aes_raw)
    LD(ctx_new,    "EVP_CIPHER_CTX_new",  fn_ctx_new)
    LD(ctx_free,   "EVP_CIPHER_CTX_free", fn_ctx_free)
    LD(c_init,     "EVP_CipherInit_ex",   fn_c_init)
    LD(c_update,   "EVP_CipherUpdate",    fn_c_update)
    LD(c_final,    "EVP_CipherFinal_ex",  fn_c_final)
    LD(c_pad,      "EVP_CIPHER_CTX_set_padding", fn_c_pad)
    LD(evp_ecb,    "EVP_aes_256_ecb",    fn_cipher_fn)
    LD(evp_cbc,    "EVP_aes_256_cbc",    fn_cipher_fn)
#undef LD
    G.ok = 1;
}

/* ══════════════════════════════════════════════════════════════════
 * THE FIX: IGE via EVP ECB — one context, ARM CE for every block
 *
 * cryptogram's bug: calls AES_encrypt()/AES_decrypt() directly.
 * These are OpenSSL's LEGACY low-level API — they use T-table AES
 * (same algorithm as tgcrypto), NOT the ENGINE-dispatched path.
 *
 * EVP_CipherUpdate() goes through:
 *   EVP dispatch → ENGINE → ARM CE (aes_v8_encrypt) → ~800 MB/s
 *
 * We create ONE EVP ECB context per ige call (no per-block malloc),
 * then call c_update(ctx, dst, &ol, src, 16) for each 16-byte block.
 * ECB mode is fine here: IGE handles its own chaining XOR.
 * ══════════════════════════════════════════════════════════════════ */
static void do_ige(const uint8_t *in, uint8_t *out, uint32_t len,
                   const uint8_t *key, const uint8_t *iv, int encrypt) {

    /* Create ONE EVP ECB context — reused for all blocks in this call */
    EVP_CIPHER_CTX *ctx = G.ctx_new();
    /* ECB always uses encrypt direction — IGE's XOR handles the chaining */
    G.c_init(ctx, G.evp_ecb(), NULL, key, NULL, encrypt);
    G.c_pad(ctx, 0);

    uint8_t iv1[16], iv2[16], saved[16];
    if (encrypt) { memcpy(iv1, iv,    16); memcpy(iv2, iv+16, 16); }
    else         { memcpy(iv2, iv,    16); memcpy(iv1, iv+16, 16); }

    uint8_t xbuf[16]; /* XOR'd input before AES */
    int ol = 0;

    for (uint32_t i = 0; i < len; i += 16) {
        const uint8_t *src = in  + i;
        uint8_t       *dst = out + i;

        /* Save original for next round's iv2/iv1 */
        memcpy(saved, src, 16);

        /* XOR input with iv1 */
        for (int j = 0; j < 16; j++) xbuf[j] = src[j] ^ iv1[j];

        /* ← KEY CHANGE: EVP_CipherUpdate → ARM CE / AES-NI engine path */
        G.c_update(ctx, dst, &ol, xbuf, 16);

        /* XOR output with iv2 */
        for (int j = 0; j < 16; j++) dst[j] ^= iv2[j];

        /* Advance IV chain */
        memcpy(iv1, dst,   16);
        memcpy(iv2, saved, 16);
    }
    G.ctx_free(ctx);
}

/* ── CTR-256: batch EVP ECB (same as cryptogram, already fast) ───── */
#define CTR_BATCH 64
static void ctr_inc(uint8_t iv[16]) {
    for (int j = 15; j >= 0 && ++iv[j] == 0; j--);
}
static void do_ctr(const uint8_t *in, uint8_t *out, uint32_t len,
                   const uint8_t *key, uint8_t iv[16], uint8_t *sp) {
    uint8_t state = *sp;

    /* Flush partial block from previous call */
    if (state != 0) {
        uint8_t ks[16]; int ol = 0, tmp = 0;
        EVP_CIPHER_CTX *ctx = G.ctx_new();
        G.c_init(ctx, G.evp_ecb(), NULL, key, NULL, 1); G.c_pad(ctx, 0);
        G.c_update(ctx, ks, &ol, iv, 16); G.c_final(ctx, ks+ol, &tmp);
        G.ctx_free(ctx);
        while (state < 16 && len > 0) { *out++ = *in++ ^ ks[state++]; len--; }
        if (state == 16) { state = 0; ctr_inc(iv); }
        if (!len) { *sp = state; return; }
    }

    /* Batch encrypt counter blocks */
    uint8_t ctr_buf[CTR_BATCH*16], ks_buf[CTR_BATCH*16];
    while (len >= 16) {
        int batch = (int)(len / 16);
        if (batch > CTR_BATCH) batch = CTR_BATCH;
        for (int b = 0; b < batch; b++) {
            memcpy(ctr_buf + b*16, iv, 16); ctr_inc(iv);
        }
        EVP_CIPHER_CTX *ctx = G.ctx_new();
        G.c_init(ctx, G.evp_ecb(), NULL, key, NULL, 1); G.c_pad(ctx, 0);
        int ol = 0, tmp = 0;
        G.c_update(ctx, ks_buf, &ol, ctr_buf, batch*16);
        G.c_final(ctx, ks_buf+ol, &tmp);
        G.ctx_free(ctx);
        int n = batch * 16;
        for (int i = 0; i < n; i++, len--) *out++ = *in++ ^ ks_buf[i];
    }
    if (len > 0) {
        uint8_t ks[16]; int ol = 0, tmp = 0;
        EVP_CIPHER_CTX *ctx = G.ctx_new();
        G.c_init(ctx, G.evp_ecb(), NULL, key, NULL, 1); G.c_pad(ctx, 0);
        G.c_update(ctx, ks, &ol, iv, 16); G.c_final(ctx, ks+ol, &tmp);
        G.ctx_free(ctx);
        for (uint32_t i = 0; i < len; i++) { *out++ = *in++ ^ ks[state++]; }
        if (state == 16) { state = 0; ctr_inc(iv); }
    }
    *sp = state;
}

/* ── CBC-256: single EVP call (OpenSSL parallelises internally) ───── */
static void do_cbc(const uint8_t *in, uint8_t *out, uint32_t len,
                   const uint8_t *key, const uint8_t *iv, int enc) {
    EVP_CIPHER_CTX *ctx = G.ctx_new();
    G.c_init(ctx, G.evp_cbc(), NULL, key, iv, enc);
    G.c_pad(ctx, 0);
    int outl = 0, tmp = 0;
    G.c_update(ctx, out, &outl, in, (int)len);
    G.c_final(ctx, out + outl, &tmp);
    G.ctx_free(ctx);
}

/* ── PQ factorisation (Brent-Pollard ρ) ─────────────────────────── */
#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 u128;
static uint64_t mulmod(uint64_t a,uint64_t b,uint64_t m){
    return (uint64_t)(((u128)a*b)%m);
}
#else
static uint64_t mulmod(uint64_t a,uint64_t b,uint64_t m){
    uint64_t r=0; a%=m;
    while(b){if(b&1){r+=a;if(r>=m)r-=m;}a<<=1;if(a>=m)a-=m;b>>=1;}
    return r;
}
#endif
static uint64_t powmod(uint64_t b,uint64_t e,uint64_t m){
    uint64_t r=1; b%=m;
    for(;e;e>>=1){if(e&1)r=mulmod(r,b,m);b=mulmod(b,b,m);}
    return r;
}
static int mr(uint64_t n,uint64_t a){
    if(n%a==0)return n==a;
    uint64_t d=n-1;int r=0;
    while(!(d&1)){d>>=1;r++;}
    uint64_t x=powmod(a,d,n);
    if(x==1||x==n-1)return 1;
    for(int i=0;i<r-1;i++){x=mulmod(x,x,n);if(x==n-1)return 1;}
    return 0;
}
static int is_prime(uint64_t n){
    if(n<2)return 0;
    static const uint64_t W[]={2,3,5,7,11,13,17,19,23,29,31,37,0};
    for(int i=0;W[i];i++){if(n==W[i])return 1;if(!mr(n,W[i]))return 0;}
    return 1;
}
static uint64_t gcd64(uint64_t a,uint64_t b){while(b){uint64_t t=b;b=a%b;a=t;}return a;}
static uint64_t absd(uint64_t a,uint64_t b){return a>b?a-b:b-a;}
static uint64_t brent(uint64_t n,uint64_t c){
    uint64_t y=2,r=1,q=1,x=0,ys=0,d;
    do{x=y;for(uint64_t i=0;i<r;i++)y=(mulmod(y,y,n)+c)%n;
       uint64_t k=0;
       do{ys=y;uint64_t lim=r-k<128?r-k:128;
          for(uint64_t i=0;i<lim;i++){y=(mulmod(y,y,n)+c)%n;q=mulmod(q,absd(x,y),n);}
          d=gcd64(q,n);k+=128;}while(k<r&&d==1);r*=2;}while(d==1);
    if(d==n){do{ys=(mulmod(ys,ys,n)+c)%n;d=gcd64(absd(x,ys),n);}while(d==1);}
    return d;
}
static uint64_t factor1(uint64_t n){
    if(n<=1||is_prime(n))return n;
    if(!(n&1))return 2;
    uint64_t d=n;
    for(uint64_t c=1;d==n;c++)d=brent(n,c);
    return is_prime(d)?d:factor1(d);
}

/* ── Backend detection ────────────────────────────────────────────── */
#if defined(__x86_64__)||defined(__i386__)
# include <cpuid.h>
static int cpu_has_aesni(void){
    unsigned a,b,c,d;
    return __get_cpuid(1,&a,&b,&c,&d)&&((c>>25)&1);
}
static const char* detect_backend(void){
    return cpu_has_aesni() ? "C/EVP+AES-NI" : "C/EVP+software";
}
#elif defined(__aarch64__)||defined(__arm__)
/* ARM: detect hardware AES by timing EVP ECB throughput once, cache result.
 * has_aesni() returns 1 when ARM Crypto Extensions are active.
 * Name kept for API compatibility with tgcrypto/cryptg. */
static int   arm_hw_cached = -1;
static const char* arm_backend_str = "C/EVP+software";

static void arm_probe(void){
    if (arm_hw_cached >= 0) return;
    if (G.ok != 1){ arm_hw_cached = 0; return; }
    static char buf[64*1024];
    static char key[32];
    EVP_CIPHER_CTX *ctx = G.ctx_new();
    G.c_init(ctx, G.evp_ecb(), NULL, (uint8_t*)key, NULL, 1);
    G.c_pad(ctx, 0);
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    int ol=0, tmp=0;
    for(int i=0;i<16;i++) G.c_update(ctx,(uint8_t*)buf,&ol,(uint8_t*)buf,sizeof(buf));
    G.c_final(ctx,(uint8_t*)buf+ol,&tmp);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    G.ctx_free(ctx);
    double elapsed = (t1.tv_sec-t0.tv_sec)+(t1.tv_nsec-t0.tv_nsec)/1e9;
    double mbps = (16.0*sizeof(buf)) / elapsed / 1e6;
    arm_hw_cached   = mbps > 300.0 ? 1 : 0;
    arm_backend_str = arm_hw_cached ? "C/EVP+ARM-CE" : "C/EVP+software";
}
static int         cpu_has_aesni(void)  { arm_probe(); return arm_hw_cached; }
static const char* detect_backend(void) { arm_probe(); return arm_backend_str; }
#else
static int cpu_has_aesni(void){return 0;}
static const char* detect_backend(void){return "C/EVP";}
#endif

/* ── Python wrappers ─────────────────────────────────────────────── */
#define CHK(c,m) do{if(!(c)){PyErr_SetString(PyExc_ValueError,(m));goto err;}}while(0)
#define NEED() do{if(G.ok!=1){PyErr_SetString(PyExc_RuntimeError,"OpenSSL not loaded");return NULL;}}while(0)

#define IGE_WRAP(fname, enc_flag)                                          \
static PyObject *fname(PyObject *self, PyObject *args) {                   \
    NEED();                                                                 \
    Py_buffer d,k,iv;                                                      \
    if(!PyArg_ParseTuple(args,"y*y*y*",&d,&k,&iv)) return NULL;           \
    CHK(d.len>0,     "data must not be empty");                            \
    CHK(d.len%16==0, "data size must be a multiple of 16 bytes");          \
    CHK(k.len==32,   "key must be 32 bytes");                              \
    CHK(iv.len==32,  "IV must be 32 bytes");                               \
    uint8_t *out=(uint8_t*)malloc(d.len);                                  \
    if(!out){PyErr_NoMemory();goto err;}                                   \
    Py_BEGIN_ALLOW_THREADS                                                  \
        do_ige(d.buf,out,(uint32_t)d.len,k.buf,iv.buf,(enc_flag));        \
    Py_END_ALLOW_THREADS                                                    \
    PyObject *r=PyBytes_FromStringAndSize((char*)out,d.len);               \
    free(out);                                                              \
    PyBuffer_Release(&d);PyBuffer_Release(&k);PyBuffer_Release(&iv);      \
    return r;                                                               \
err:PyBuffer_Release(&d);PyBuffer_Release(&k);PyBuffer_Release(&iv);      \
    return NULL;                                                            \
}

IGE_WRAP(py_ige256_encrypt, 1)
IGE_WRAP(py_ige256_decrypt, 0)
IGE_WRAP(py_encrypt_ige,    1)
IGE_WRAP(py_decrypt_ige,    0)

static PyObject *py_ctr256(PyObject *self, PyObject *args) {
    NEED();
    Py_buffer d,k,iv,st;
    if(!PyArg_ParseTuple(args,"y*y*y*y*",&d,&k,&iv,&st)) return NULL;
    CHK(d.len>0,            "data must not be empty");
    CHK(k.len==32,          "key must be 32 bytes");
    CHK(iv.len==16,         "IV must be 16 bytes");
    CHK(st.len==1,          "state must be 1 byte");
    CHK(*(uint8_t*)st.buf<=15,"state must be 0-15");
    uint8_t *out=(uint8_t*)malloc(d.len);
    uint8_t iv_cp[16]; uint8_t s=*(uint8_t*)st.buf;
    memcpy(iv_cp,iv.buf,16);
    if(!out){PyErr_NoMemory();goto err;}
    Py_BEGIN_ALLOW_THREADS
        do_ctr(d.buf,out,(uint32_t)d.len,k.buf,iv_cp,&s);
    Py_END_ALLOW_THREADS
    memcpy(iv.buf,iv_cp,16); *(uint8_t*)st.buf=s;
    PyObject *r=PyBytes_FromStringAndSize((char*)out,d.len);
    free(out);
    PyBuffer_Release(&d);PyBuffer_Release(&k);
    PyBuffer_Release(&iv);PyBuffer_Release(&st);
    return r;
err:PyBuffer_Release(&d);PyBuffer_Release(&k);
    PyBuffer_Release(&iv);PyBuffer_Release(&st);
    return NULL;
}

#define CBC_WRAP(fname, enc_flag)                                          \
static PyObject *fname(PyObject *self, PyObject *args) {                   \
    NEED();                                                                 \
    Py_buffer d,k,iv;                                                      \
    if(!PyArg_ParseTuple(args,"y*y*y*",&d,&k,&iv)) return NULL;           \
    CHK(d.len>0,     "data must not be empty");                            \
    CHK(d.len%16==0, "data size must be a multiple of 16 bytes");          \
    CHK(k.len==32,   "key must be 32 bytes");                              \
    CHK(iv.len==16,  "IV must be 16 bytes");                               \
    uint8_t *out=(uint8_t*)malloc(d.len);                                  \
    if(!out){PyErr_NoMemory();goto err;}                                   \
    Py_BEGIN_ALLOW_THREADS                                                  \
        do_cbc(d.buf,out,(uint32_t)d.len,k.buf,iv.buf,(enc_flag));        \
    Py_END_ALLOW_THREADS                                                    \
    PyObject *r=PyBytes_FromStringAndSize((char*)out,d.len);               \
    free(out);                                                              \
    PyBuffer_Release(&d);PyBuffer_Release(&k);PyBuffer_Release(&iv);      \
    return r;                                                               \
err:PyBuffer_Release(&d);PyBuffer_Release(&k);PyBuffer_Release(&iv);      \
    return NULL;                                                            \
}

CBC_WRAP(py_cbc256_encrypt, 1)
CBC_WRAP(py_cbc256_decrypt, 0)

static PyObject *py_factorize(PyObject *self, PyObject *args){
    unsigned long long pq;
    if(!PyArg_ParseTuple(args,"K",&pq)) return NULL;
    uint64_t p=factor1((uint64_t)pq), q=(uint64_t)pq/p;
    if(p>q){uint64_t t=p;p=q;q=t;}
    return Py_BuildValue("(KK)",(unsigned long long)p,(unsigned long long)q);
}

static PyObject *py_has_aesni(PyObject *s,PyObject *a){
    return PyBool_FromLong(cpu_has_aesni());
}

static PyObject *py_get_backend(PyObject *s,PyObject *a){
    return PyUnicode_FromString(G.ok==1 ? detect_backend() : "Python/fallback");
}

static PyMethodDef methods[]={
    {"ige256_encrypt",    py_ige256_encrypt, METH_VARARGS, "IGE-256 encrypt"},
    {"ige256_decrypt",    py_ige256_decrypt, METH_VARARGS, "IGE-256 decrypt"},
    {"ctr256_encrypt",    py_ctr256,         METH_VARARGS, "CTR-256 encrypt"},
    {"ctr256_decrypt",    py_ctr256,         METH_VARARGS, "CTR-256 decrypt"},
    {"cbc256_encrypt",    py_cbc256_encrypt, METH_VARARGS, "CBC-256 encrypt"},
    {"cbc256_decrypt",    py_cbc256_decrypt, METH_VARARGS, "CBC-256 decrypt"},
    {"encrypt_ige",       py_encrypt_ige,    METH_VARARGS, "IGE-256 encrypt (cryptg API)"},
    {"decrypt_ige",       py_decrypt_ige,    METH_VARARGS, "IGE-256 decrypt (cryptg API)"},
    {"factorize_pq_pair", py_factorize,      METH_VARARGS, "Factorise PQ"},
    {"has_aesni",         py_has_aesni,      METH_NOARGS,  "True if AES-NI (x86)"},
    {"get_backend",       py_get_backend,    METH_NOARGS,  "Backend name string"},
    {NULL,NULL,0,NULL}
};

static struct PyModuleDef moddef={
    PyModuleDef_HEAD_INIT,"_cipheron",
    "cipheron — EVP-routed IGE for full ARM-CE / AES-NI acceleration",
    -1, methods
};

PyMODINIT_FUNC PyInit__cipheron(void){
    ssl_load();
    if(G.ok!=1){
        PyErr_SetString(PyExc_ImportError,"cipheron: OpenSSL not found");
        return NULL;
    }
    return PyModule_Create(&moddef);
}
