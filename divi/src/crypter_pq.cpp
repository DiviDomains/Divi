// Copyright (c) 2026 The DIVI Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// DIP-PQ-0 (§2.2): Self-contained pure-integer C++11 implementation of
// RFC 9106 Argon2id v0x13 and XChaCha20-Poly1305 AEAD for CMasterKey
// nDerivationMethod = 1 (exact bit-for-bit parity with IronDivi at_rest.rs).
// Strictly zero floating-point types or operations (-fno-fast-math safe).

#include "crypter_pq.h"

#include <cstring>

namespace divi_pq
{
namespace
{

inline uint32_t load_le32(const uint8_t* p)
{
    return (static_cast<uint32_t>(p[0])) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline void store_le32(uint8_t* p, uint32_t v)
{
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

inline uint64_t load_le64(const uint8_t* p)
{
    return (static_cast<uint64_t>(p[0])) |
           (static_cast<uint64_t>(p[1]) << 8) |
           (static_cast<uint64_t>(p[2]) << 16) |
           (static_cast<uint64_t>(p[3]) << 24) |
           (static_cast<uint64_t>(p[4]) << 32) |
           (static_cast<uint64_t>(p[5]) << 40) |
           (static_cast<uint64_t>(p[6]) << 48) |
           (static_cast<uint64_t>(p[7]) << 56);
}

inline void store_le64(uint8_t* p, uint64_t v)
{
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
    p[4] = static_cast<uint8_t>(v >> 32);
    p[5] = static_cast<uint8_t>(v >> 40);
    p[6] = static_cast<uint8_t>(v >> 48);
    p[7] = static_cast<uint8_t>(v >> 56);
}

inline uint32_t rotl32(uint32_t x, unsigned int n)
{
    return (x << n) | (x >> (32u - n));
}

inline uint64_t rotr64(uint64_t x, unsigned int n)
{
    return (x >> n) | (x << (64u - n));
}

inline void secure_wipe(void* ptr, size_t len)
{
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (len-- > 0)
    {
        *p++ = 0u;
    }
}

// ============================================================================
// RFC 7693 BLAKE2b (1..64 byte digest, unkeyed)
// ============================================================================

static const uint64_t BLAKE2B_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static const uint8_t BLAKE2B_SIGMA[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    { 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    { 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    { 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    { 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    { 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    { 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    { 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    { 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 }
};

struct Blake2bCtx
{
    uint64_t h[8];
    uint64_t t[2];
    uint8_t  buf[128];
    size_t   buf_len;
    size_t   out_len;
};

inline void blake2b_g(uint64_t v[16], size_t a, size_t b, size_t c, size_t d, uint64_t x, uint64_t y)
{
    v[a] = v[a] + v[b] + x;
    v[d] = rotr64(v[d] ^ v[a], 32);
    v[c] = v[c] + v[d];
    v[b] = rotr64(v[b] ^ v[c], 24);
    v[a] = v[a] + v[b] + y;
    v[d] = rotr64(v[d] ^ v[a], 16);
    v[c] = v[c] + v[d];
    v[b] = rotr64(v[b] ^ v[c], 63);
}

static void blake2b_compress(Blake2bCtx* ctx, bool is_last)
{
    uint64_t v[16];
    uint64_t m[16];
    for (size_t i = 0; i < 8; ++i)
    {
        v[i] = ctx->h[i];
        v[i + 8] = BLAKE2B_IV[i];
    }
    v[12] ^= ctx->t[0];
    v[13] ^= ctx->t[1];
    if (is_last)
    {
        v[14] = ~v[14];
    }
    for (size_t i = 0; i < 16; ++i)
    {
        m[i] = load_le64(&ctx->buf[i * 8]);
    }
    for (size_t r = 0; r < 12; ++r)
    {
        const uint8_t* s = BLAKE2B_SIGMA[r];
        blake2b_g(v, 0, 4,  8, 12, m[s[0]],  m[s[1]]);
        blake2b_g(v, 1, 5,  9, 13, m[s[2]],  m[s[3]]);
        blake2b_g(v, 2, 6, 10, 14, m[s[4]],  m[s[5]]);
        blake2b_g(v, 3, 7, 11, 15, m[s[6]],  m[s[7]]);
        blake2b_g(v, 0, 5, 10, 15, m[s[8]],  m[s[9]]);
        blake2b_g(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        blake2b_g(v, 2, 7,  8, 13, m[s[12]], m[s[13]]);
        blake2b_g(v, 3, 4,  9, 14, m[s[14]], m[s[15]]);
    }
    for (size_t i = 0; i < 8; ++i)
    {
        ctx->h[i] ^= v[i] ^ v[i + 8];
    }
}

static void blake2b_init(Blake2bCtx* ctx, size_t out_len)
{
    for (size_t i = 0; i < 8; ++i)
    {
        ctx->h[i] = BLAKE2B_IV[i];
    }
    ctx->h[0] ^= 0x01010000ULL ^ static_cast<uint64_t>(out_len);
    ctx->t[0] = 0;
    ctx->t[1] = 0;
    std::memset(ctx->buf, 0, sizeof(ctx->buf));
    ctx->buf_len = 0;
    ctx->out_len = out_len;
}

static void blake2b_update(Blake2bCtx* ctx, const uint8_t* data, size_t len)
{
    if (len == 0)
    {
        return;
    }
    while (len > 0)
    {
        if (ctx->buf_len == 128u)
        {
            ctx->t[0] += 128u;
            if (ctx->t[0] < 128u)
            {
                ctx->t[1] += 1u;
            }
            blake2b_compress(ctx, false);
            ctx->buf_len = 0;
        }
        size_t take = 128u - ctx->buf_len;
        if (take > len)
        {
            take = len;
        }
        std::memcpy(&ctx->buf[ctx->buf_len], data, take);
        ctx->buf_len += take;
        data += take;
        len -= take;
    }
}

static void blake2b_final(Blake2bCtx* ctx, uint8_t* out)
{
    ctx->t[0] += static_cast<uint64_t>(ctx->buf_len);
    if (ctx->t[0] < static_cast<uint64_t>(ctx->buf_len))
    {
        ctx->t[1] += 1u;
    }
    while (ctx->buf_len < 128u)
    {
        ctx->buf[ctx->buf_len++] = 0u;
    }
    blake2b_compress(ctx, true);

    uint8_t full[64];
    for (size_t i = 0; i < 8; ++i)
    {
        store_le64(&full[i * 8], ctx->h[i]);
    }
    std::memcpy(out, full, ctx->out_len);
    secure_wipe(full, sizeof(full));
    secure_wipe(ctx, sizeof(*ctx));
}

static void blake2b_long(uint8_t* out, size_t out_len, const uint8_t* in, size_t in_len)
{
    uint8_t outlen_le[4];
    store_le32(outlen_le, static_cast<uint32_t>(out_len));

    if (out_len <= 64u)
    {
        Blake2bCtx ctx;
        blake2b_init(&ctx, out_len);
        blake2b_update(&ctx, outlen_le, 4u);
        blake2b_update(&ctx, in, in_len);
        blake2b_final(&ctx, out);
        return;
    }

    uint8_t prev[64];
    Blake2bCtx ctx;
    blake2b_init(&ctx, 64u);
    blake2b_update(&ctx, outlen_le, 4u);
    blake2b_update(&ctx, in, in_len);
    blake2b_final(&ctx, prev);
    std::memcpy(out, prev, 32u);
    out += 32u;
    size_t to_produce = out_len - 32u;

    while (to_produce > 64u)
    {
        uint8_t next[64];
        blake2b_init(&ctx, 64u);
        blake2b_update(&ctx, prev, 64u);
        blake2b_final(&ctx, next);
        std::memcpy(out, next, 32u);
        std::memcpy(prev, next, 64u);
        out += 32u;
        to_produce -= 32u;
    }

    blake2b_init(&ctx, to_produce);
    blake2b_update(&ctx, prev, 64u);
    blake2b_final(&ctx, out);
    secure_wipe(prev, sizeof(prev));
}

// ============================================================================
// RFC 9106 Argon2id v0x13 Compression & Indexing
// ============================================================================

struct Argon2Block
{
    uint64_t v[128];
};

inline uint64_t f_blamka(uint64_t x, uint64_t y)
{
    uint64_t m = static_cast<uint64_t>(static_cast<uint32_t>(x)) *
                 static_cast<uint64_t>(static_cast<uint32_t>(y));
    return x + y + (m << 1);
}

inline void g_blamka(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d)
{
    a = f_blamka(a, b);
    d = rotr64(d ^ a, 32);
    c = f_blamka(c, d);
    b = rotr64(b ^ c, 24);
    a = f_blamka(a, b);
    d = rotr64(d ^ a, 16);
    c = f_blamka(c, d);
    b = rotr64(b ^ c, 63);
}

inline void blamka_round(
    uint64_t& v0,  uint64_t& v1,  uint64_t& v2,  uint64_t& v3,
    uint64_t& v4,  uint64_t& v5,  uint64_t& v6,  uint64_t& v7,
    uint64_t& v8,  uint64_t& v9,  uint64_t& v10, uint64_t& v11,
    uint64_t& v12, uint64_t& v13, uint64_t& v14, uint64_t& v15)
{
    g_blamka(v0, v4,  v8, 12 == 12 ? v12 : v12);
    g_blamka(v1, v5,  v9, v13);
    g_blamka(v2, v6, v10, v14);
    g_blamka(v3, v7, v11, v15);
    g_blamka(v0, v5, v10, v15);
    g_blamka(v1, v6, v11, v12);
    g_blamka(v2, v7,  v8, v13);
    g_blamka(v3, v4,  v9, v14);
}

static void argon2_fill_block(
    const Argon2Block& prev_block,
    const Argon2Block& ref_block,
    Argon2Block& next_block,
    bool with_xor)
{
    Argon2Block block_r;
    Argon2Block block_tmp;
    for (size_t i = 0; i < 128; ++i)
    {
        block_r.v[i] = ref_block.v[i] ^ prev_block.v[i];
        block_tmp.v[i] = block_r.v[i];
    }
    if (with_xor)
    {
        for (size_t i = 0; i < 128; ++i)
        {
            block_tmp.v[i] ^= next_block.v[i];
        }
    }

    for (size_t i = 0; i < 8; ++i)
    {
        size_t base = i * 16;
        blamka_round(
            block_r.v[base + 0],  block_r.v[base + 1],  block_r.v[base + 2],  block_r.v[base + 3],
            block_r.v[base + 4],  block_r.v[base + 5],  block_r.v[base + 6],  block_r.v[base + 7],
            block_r.v[base + 8],  block_r.v[base + 9],  block_r.v[base + 10], block_r.v[base + 11],
            block_r.v[base + 12], block_r.v[base + 13], block_r.v[base + 14], block_r.v[base + 15]);
    }

    for (size_t i = 0; i < 8; ++i)
    {
        size_t col = i * 2;
        blamka_round(
            block_r.v[col + 0],   block_r.v[col + 1],
            block_r.v[col + 16],  block_r.v[col + 17],
            block_r.v[col + 32],  block_r.v[col + 33],
            block_r.v[col + 48],  block_r.v[col + 49],
            block_r.v[col + 64],  block_r.v[col + 65],
            block_r.v[col + 80],  block_r.v[col + 81],
            block_r.v[col + 96],  block_r.v[col + 97],
            block_r.v[col + 112], block_r.v[col + 113]);
    }

    for (size_t i = 0; i < 128; ++i)
    {
        next_block.v[i] = block_tmp.v[i] ^ block_r.v[i];
    }
}

static void argon2_next_addresses(
    Argon2Block& address_block,
    Argon2Block& input_block,
    const Argon2Block& zero_block)
{
    input_block.v[6] += 1u;
    argon2_fill_block(zero_block, input_block, address_block, false);
    argon2_fill_block(zero_block, address_block, address_block, false);
}

static uint32_t argon2_index_alpha(
    uint32_t pass,
    uint32_t lane,
    uint32_t slice,
    uint32_t index,
    uint32_t lane_length,
    uint32_t segment_length,
    uint32_t pseudo_rand,
    bool same_lane)
{
    uint32_t reference_area_size;
    if (pass == 0u)
    {
        if (slice == 0u)
        {
            reference_area_size = index - 1u;
        }
        else if (same_lane)
        {
            reference_area_size = slice * segment_length + index - 1u;
        }
        else
        {
            reference_area_size = slice * segment_length - ((index == 0u) ? 1u : 0u);
        }
    }
    else
    {
        if (same_lane)
        {
            reference_area_size = lane_length - segment_length + index - 1u;
        }
        else
        {
            reference_area_size = lane_length - segment_length - ((index == 0u) ? 1u : 0u);
        }
    }

    uint64_t relative_position = pseudo_rand;
    relative_position = (relative_position * relative_position) >> 32;
    relative_position = reference_area_size - 1u - ((reference_area_size * relative_position) >> 32);

    uint32_t start_position = 0u;
    if (pass != 0u)
    {
        start_position = (slice == 3u) ? 0u : ((slice + 1u) * segment_length);
    }
    (void)lane;
    return (start_position + static_cast<uint32_t>(relative_position)) % lane_length;
}

// ============================================================================
// XChaCha20 & Poly1305 Primitives (RFC 8439 + draft-irtf-cfrg-xchacha)
// ============================================================================

inline void chacha_quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d)
{
    a += b; d = rotl32(d ^ a, 16);
    c += d; b = rotl32(b ^ c, 12);
    a += b; d = rotl32(d ^ a, 8);
    c += d; b = rotl32(b ^ c, 7);
}

static void chacha20_rounds(uint32_t s[16])
{
    for (int i = 0; i < 10; ++i)
    {
        chacha_quarter_round(s[0], s[4], s[8],  s[12]);
        chacha_quarter_round(s[1], s[5], s[9],  s[13]);
        chacha_quarter_round(s[2], s[6], s[10], s[14]);
        chacha_quarter_round(s[3], s[7], s[11], s[15]);

        chacha_quarter_round(s[0], s[5], s[10], s[15]);
        chacha_quarter_round(s[1], s[6], s[11], s[12]);
        chacha_quarter_round(s[2], s[7], s[8],  s[13]);
        chacha_quarter_round(s[3], s[4], s[9],  s[14]);
    }
}

static void hchacha20(const uint8_t key[32], const uint8_t nonce16[16], uint8_t out_subkey[32])
{
    uint32_t s[16];
    s[0]  = 0x61707865u;
    s[1]  = 0x3320646eu;
    s[2]  = 0x79622d32u;
    s[3]  = 0x6b206574u;
    for (size_t i = 0; i < 8; ++i)
    {
        s[4 + i] = load_le32(&key[i * 4]);
    }
    for (size_t i = 0; i < 4; ++i)
    {
        s[12 + i] = load_le32(&nonce16[i * 4]);
    }

    chacha20_rounds(s);

    for (size_t i = 0; i < 4; ++i)
    {
        store_le32(&out_subkey[i * 4], s[i]);
        store_le32(&out_subkey[16 + i * 4], s[12 + i]);
    }
    secure_wipe(s, sizeof(s));
}

static void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce12[12], uint8_t out_block[64])
{
    uint32_t init[16];
    uint32_t work[16];
    init[0]  = 0x61707865u;
    init[1]  = 0x3320646eu;
    init[2]  = 0x79622d32u;
    init[3]  = 0x6b206574u;
    for (size_t i = 0; i < 8; ++i)
    {
        init[4 + i] = load_le32(&key[i * 4]);
    }
    init[12] = counter;
    init[13] = load_le32(&nonce12[0]);
    init[14] = load_le32(&nonce12[4]);
    init[15] = load_le32(&nonce12[8]);

    std::memcpy(work, init, sizeof(init));
    chacha20_rounds(work);

    for (size_t i = 0; i < 16; ++i)
    {
        store_le32(&out_block[i * 4], work[i] + init[i]);
    }
    secure_wipe(init, sizeof(init));
    secure_wipe(work, sizeof(work));
}

static void chacha20_xor(
    const uint8_t key[32],
    uint32_t initial_counter,
    const uint8_t nonce12[12],
    const uint8_t* in,
    size_t len,
    uint8_t* out)
{
    uint8_t block[64];
    uint32_t counter = initial_counter;
    while (len > 0)
    {
        chacha20_block(key, counter++, nonce12, block);
        size_t take = (len < 64u) ? len : 64u;
        for (size_t i = 0; i < take; ++i)
        {
            out[i] = in[i] ^ block[i];
        }
        in += take;
        out += take;
        len -= take;
    }
    secure_wipe(block, sizeof(block));
}

// Pure-integer 26-bit limb Poly1305 (RFC 8439 §2.5)
struct Poly1305State
{
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
};

static void poly1305_init(Poly1305State* st, const uint8_t key[32])
{
    st->r[0] = (load_le32(&key[0])) & 0x3ffffffu;
    st->r[1] = (load_le32(&key[3]) >> 2) & 0x3ffff03u;
    st->r[2] = (load_le32(&key[6]) >> 4) & 0x3ffc0ffu;
    st->r[3] = (load_le32(&key[9]) >> 6) & 0x3f03fffu;
    st->r[4] = (load_le32(&key[12]) >> 8) & 0x00fffffu;

    for (int i = 0; i < 5; ++i)
    {
        st->h[i] = 0u;
    }
    for (int i = 0; i < 4; ++i)
    {
        st->pad[i] = load_le32(&key[16 + i * 4]);
    }
}

static void poly1305_blocks(Poly1305State* st, const uint8_t* m, size_t bytes)
{
    const uint32_t hibit = (1u << 24);
    uint32_t r0 = st->r[0];
    uint32_t r1 = st->r[1];
    uint32_t r2 = st->r[2];
    uint32_t r3 = st->r[3];
    uint32_t r4 = st->r[4];

    uint32_t s1 = r1 * 5u;
    uint32_t s2 = r2 * 5u;
    uint32_t s3 = r3 * 5u;
    uint32_t s4 = r4 * 5u;

    uint32_t h0 = st->h[0];
    uint32_t h1 = st->h[1];
    uint32_t h2 = st->h[2];
    uint32_t h3 = st->h[3];
    uint32_t h4 = st->h[4];

    while (bytes >= 16u)
    {
        h0 += (load_le32(&m[0])) & 0x3ffffffu;
        h1 += (load_le32(&m[3]) >> 2) & 0x3ffffffu;
        h2 += (load_le32(&m[6]) >> 4) & 0x3ffffffu;
        h3 += (load_le32(&m[9]) >> 6) & 0x3ffffffu;
        h4 += (load_le32(&m[12]) >> 8) | hibit;

        uint64_t d0 = static_cast<uint64_t>(h0) * r0 + static_cast<uint64_t>(h1) * s4 +
                      static_cast<uint64_t>(h2) * s3 + static_cast<uint64_t>(h3) * s2 +
                      static_cast<uint64_t>(h4) * s1;
        uint64_t d1 = static_cast<uint64_t>(h0) * r1 + static_cast<uint64_t>(h1) * r0 +
                      static_cast<uint64_t>(h2) * s4 + static_cast<uint64_t>(h3) * s3 +
                      static_cast<uint64_t>(h4) * s2;
        uint64_t d2 = static_cast<uint64_t>(h0) * r2 + static_cast<uint64_t>(h1) * r1 +
                      static_cast<uint64_t>(h2) * r0 + static_cast<uint64_t>(h3) * s4 +
                      static_cast<uint64_t>(h4) * s3;
        uint64_t d3 = static_cast<uint64_t>(h0) * r3 + static_cast<uint64_t>(h1) * r2 +
                      static_cast<uint64_t>(h2) * r1 + static_cast<uint64_t>(h3) * r0 +
                      static_cast<uint64_t>(h4) * s4;
        uint64_t d4 = static_cast<uint64_t>(h0) * r4 + static_cast<uint64_t>(h1) * r3 +
                      static_cast<uint64_t>(h2) * r2 + static_cast<uint64_t>(h3) * r1 +
                      static_cast<uint64_t>(h4) * r0;

        uint32_t c;
        c = static_cast<uint32_t>(d0 >> 26); h0 = static_cast<uint32_t>(d0) & 0x3ffffffu; d1 += c;
        c = static_cast<uint32_t>(d1 >> 26); h1 = static_cast<uint32_t>(d1) & 0x3ffffffu; d2 += c;
        c = static_cast<uint32_t>(d2 >> 26); h2 = static_cast<uint32_t>(d2) & 0x3ffffffu; d3 += c;
        c = static_cast<uint32_t>(d3 >> 26); h3 = static_cast<uint32_t>(d3) & 0x3ffffffu; d4 += c;
        c = static_cast<uint32_t>(d4 >> 26); h4 = static_cast<uint32_t>(d4) & 0x3ffffffu; h0 += c * 5u;
        c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c;

        m += 16u;
        bytes -= 16u;
    }

    st->h[0] = h0;
    st->h[1] = h1;
    st->h[2] = h2;
    st->h[3] = h3;
    st->h[4] = h4;
}

static void poly1305_update_padded(Poly1305State* st, const uint8_t* data, size_t len)
{
    if (len == 0)
    {
        return;
    }
    size_t full_bytes = (len / 16u) * 16u;
    if (full_bytes > 0)
    {
        poly1305_blocks(st, data, full_bytes);
    }
    size_t rem = len - full_bytes;
    if (rem > 0)
    {
        uint8_t tail[16];
        std::memset(tail, 0, sizeof(tail));
        std::memcpy(tail, data + full_bytes, rem);
        poly1305_blocks(st, tail, 16u);
        secure_wipe(tail, sizeof(tail));
    }
}

static void poly1305_final(Poly1305State* st, uint8_t mac[16])
{
    uint32_t h0 = st->h[0];
    uint32_t h1 = st->h[1];
    uint32_t h2 = st->h[2];
    uint32_t h3 = st->h[3];
    uint32_t h4 = st->h[4];

    uint32_t c;
    c = h1 >> 26; h1 &= 0x3ffffffu; h2 += c;
    c = h2 >> 26; h2 &= 0x3ffffffu; h3 += c;
    c = h3 >> 26; h3 &= 0x3ffffffu; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffffu; h0 += c * 5u;
    c = h0 >> 26; h0 &= 0x3ffffffu; h1 += c;

    uint32_t g0 = h0 + 5u; c = g0 >> 26; g0 &= 0x3ffffffu;
    uint32_t g1 = h1 + c;  c = g1 >> 26; g1 &= 0x3ffffffu;
    uint32_t g2 = h2 + c;  c = g2 >> 26; g2 &= 0x3ffffffu;
    uint32_t g3 = h3 + c;  c = g3 >> 26; g3 &= 0x3ffffffu;
    uint32_t g4 = h4 + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1u;
    g0 &= mask;
    g1 &= mask;
    g2 &= mask;
    g3 &= mask;
    g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    uint64_t f;
    f = static_cast<uint64_t>(h0) | (static_cast<uint64_t>(h1) << 26);
    uint32_t w0 = static_cast<uint32_t>(f);
    f = (static_cast<uint64_t>(h1 >> 6)) | (static_cast<uint64_t>(h2) << 20) | (static_cast<uint64_t>(h3) << 46);
    uint32_t w1 = static_cast<uint32_t>(f);
    f = (static_cast<uint64_t>(h3 >> 12)) | (static_cast<uint64_t>(h4) << 14);
    uint32_t w2 = static_cast<uint32_t>(f);
    uint32_t w3 = (h4 >> 18);

    uint64_t acc = static_cast<uint64_t>(w0) + st->pad[0];
    store_le32(&mac[0], static_cast<uint32_t>(acc));
    acc = static_cast<uint64_t>(w1) + st->pad[1] + (acc >> 32);
    store_le32(&mac[4], static_cast<uint32_t>(acc));
    acc = static_cast<uint64_t>(w2) + st->pad[2] + (acc >> 32);
    store_le32(&mac[8], static_cast<uint32_t>(acc));
    acc = static_cast<uint64_t>(w3) + st->pad[3] + (acc >> 32);
    store_le32(&mac[12], static_cast<uint32_t>(acc));

    secure_wipe(st, sizeof(*st));
}

static void poly1305_aead_tag(
    const uint8_t otk[32],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* ct,
    size_t ct_len,
    uint8_t out_tag[16])
{
    Poly1305State st;
    poly1305_init(&st, otk);
    poly1305_update_padded(&st, aad, aad_len);
    poly1305_update_padded(&st, ct, ct_len);

    uint8_t lengths[16];
    store_le64(&lengths[0], static_cast<uint64_t>(aad_len));
    store_le64(&lengths[8], static_cast<uint64_t>(ct_len));
    poly1305_blocks(&st, lengths, 16u);
    poly1305_final(&st, out_tag);
    secure_wipe(lengths, sizeof(lengths));
}

} // anonymous namespace

bool KdfParamsV2::IsValid() const
{
    if (t < 1u || p < 1u || p > 0x00ffffffu)
    {
        return false;
    }
    uint64_t min_m = static_cast<uint64_t>(p) * 8u;
    if (static_cast<uint64_t>(m_kib) < min_m || m_kib > MAX_M_KIB)
    {
        return false;
    }
    return true;
}

std::vector<uint8_t> KdfParamsV2::Encode() const
{
    std::vector<uint8_t> out(ENCODED_LEN, 0u);
    out[0] = VERSION;
    store_le32(&out[1], m_kib);
    store_le32(&out[5], t);
    store_le32(&out[9], p);
    return out;
}

bool KdfParamsV2::Decode(const uint8_t* data, size_t len, KdfParamsV2& out)
{
    if (data == nullptr || len != ENCODED_LEN || data[0] != VERSION)
    {
        return false;
    }
    KdfParamsV2 candidate(
        load_le32(&data[1]),
        load_le32(&data[5]),
        load_le32(&data[9]));
    if (!candidate.IsValid())
    {
        return false;
    }
    out = candidate;
    return true;
}

bool KdfParamsV2::Decode(const std::vector<uint8_t>& data, KdfParamsV2& out)
{
    return Decode(data.empty() ? nullptr : data.data(), data.size(), out);
}

bool Argon2idHash32(
    const uint8_t* password,
    size_t password_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t m_kib,
    uint32_t t_cost,
    uint32_t p_lanes,
    uint8_t out_key[32])
{
    if (out_key == nullptr || salt == nullptr || salt_len < 8u)
    {
        return false;
    }
    KdfParamsV2 params(m_kib, t_cost, p_lanes);
    if (!params.IsValid())
    {
        return false;
    }

    const uint32_t tag_len = 32u;
    const uint32_t version = 0x13u; // 19
    const uint32_t type    = 2u;    // Argon2id

    // 1. Compute H_0 (64 bytes)
    Blake2bCtx h0_ctx;
    blake2b_init(&h0_ctx, 64u);
    uint8_t tmp4[4];

    store_le32(tmp4, p_lanes);                       blake2b_update(&h0_ctx, tmp4, 4u);
    store_le32(tmp4, tag_len);                       blake2b_update(&h0_ctx, tmp4, 4u);
    store_le32(tmp4, m_kib);                         blake2b_update(&h0_ctx, tmp4, 4u);
    store_le32(tmp4, t_cost);                        blake2b_update(&h0_ctx, tmp4, 4u);
    store_le32(tmp4, version);                       blake2b_update(&h0_ctx, tmp4, 4u);
    store_le32(tmp4, type);                          blake2b_update(&h0_ctx, tmp4, 4u);
    store_le32(tmp4, static_cast<uint32_t>(password_len));
    blake2b_update(&h0_ctx, tmp4, 4u);
    if (password != nullptr && password_len > 0)
    {
        blake2b_update(&h0_ctx, password, password_len);
    }
    store_le32(tmp4, static_cast<uint32_t>(salt_len));
    blake2b_update(&h0_ctx, tmp4, 4u);
    blake2b_update(&h0_ctx, salt, salt_len);
    store_le32(tmp4, 0u); blake2b_update(&h0_ctx, tmp4, 4u); // secret len = 0
    store_le32(tmp4, 0u); blake2b_update(&h0_ctx, tmp4, 4u); // ad len = 0

    uint8_t h0_plus_8[72];
    blake2b_final(&h0_ctx, h0_plus_8);

    // 2. Allocate memory blocks: m' = 4 * p * floor(m_kib / (4 * p))
    uint32_t segment_length = m_kib / (p_lanes * 4u);
    if (segment_length < 2u)
    {
        segment_length = 2u;
    }
    uint32_t lane_length = segment_length * 4u;
    uint32_t memory_blocks = lane_length * p_lanes;

    std::vector<Argon2Block> memory(memory_blocks);

    // 3. Initialize B[i][0] and B[i][1] for each lane
    uint8_t block_bytes[1024];
    for (uint32_t l = 0; l < p_lanes; ++l)
    {
        for (uint32_t j = 0; j < 2u; ++j)
        {
            store_le32(&h0_plus_8[64], j);
            store_le32(&h0_plus_8[68], l);
            blake2b_long(block_bytes, 1024u, h0_plus_8, 72u);
            Argon2Block& blk = memory[l * lane_length + j];
            for (size_t w = 0; w < 128; ++w)
            {
                blk.v[w] = load_le64(&block_bytes[w * 8]);
            }
        }
    }
    secure_wipe(block_bytes, sizeof(block_bytes));
    secure_wipe(h0_plus_8, sizeof(h0_plus_8));

    // 4. Fill segments across passes and slices
    Argon2Block zero_block;
    std::memset(&zero_block, 0, sizeof(zero_block));

    for (uint32_t r = 0; r < t_cost; ++r)
    {
        for (uint32_t s = 0; s < 4u; ++s)
        {
            for (uint32_t l = 0; l < p_lanes; ++l)
            {
                bool data_independent = (r == 0u) && (s < 2u);
                Argon2Block input_block;
                Argon2Block address_block;
                std::memset(&input_block, 0, sizeof(input_block));
                std::memset(&address_block, 0, sizeof(address_block));

                if (data_independent)
                {
                    input_block.v[0] = r;
                    input_block.v[1] = l;
                    input_block.v[2] = s;
                    input_block.v[3] = memory_blocks;
                    input_block.v[4] = t_cost;
                    input_block.v[5] = type;
                    argon2_next_addresses(address_block, input_block, zero_block);
                }

                uint32_t starting_index = (r == 0u && s == 0u) ? 2u : 0u;
                uint32_t cur_offset = l * lane_length + s * segment_length + starting_index;
                uint32_t prev_offset = (cur_offset % lane_length == 0u)
                    ? (cur_offset + lane_length - 1u)
                    : (cur_offset - 1u);

                for (uint32_t i = starting_index; i < segment_length; ++i, ++cur_offset, ++prev_offset)
                {
                    if (cur_offset % lane_length == 1u)
                    {
                        prev_offset = cur_offset - 1u;
                    }

                    uint64_t pseudo_rand;
                    if (data_independent)
                    {
                        if (i % 128u == 0u && i != 0u)
                        {
                            argon2_next_addresses(address_block, input_block, zero_block);
                        }
                        pseudo_rand = address_block.v[i % 128u];
                    }
                    else
                    {
                        pseudo_rand = memory[prev_offset].v[0];
                    }

                    uint32_t ref_lane = static_cast<uint32_t>((pseudo_rand >> 32) % p_lanes);
                    if (r == 0u && s == 0u)
                    {
                        ref_lane = l;
                    }
                    uint32_t ref_index = argon2_index_alpha(
                        r,
                        l,
                        s,
                        i,
                        lane_length,
                        segment_length,
                        static_cast<uint32_t>(pseudo_rand),
                        ref_lane == l);

                    const Argon2Block& ref_block = memory[ref_lane * lane_length + ref_index];
                    Argon2Block& curr_block = memory[cur_offset];
                    argon2_fill_block(memory[prev_offset], ref_block, curr_block, r != 0u);
                }
            }
        }
    }

    // 5. Finalize: XOR last column across lanes and hash with H'(32, C)
    Argon2Block final_block = memory[lane_length - 1u];
    for (uint32_t l = 1u; l < p_lanes; ++l)
    {
        const Argon2Block& lane_last = memory[l * lane_length + lane_length - 1u];
        for (size_t w = 0; w < 128; ++w)
        {
            final_block.v[w] ^= lane_last.v[w];
        }
    }

    for (size_t w = 0; w < 128; ++w)
    {
        store_le64(&block_bytes[w * 8], final_block.v[w]);
    }
    blake2b_long(out_key, tag_len, block_bytes, 1024u);

    secure_wipe(block_bytes, sizeof(block_bytes));
    secure_wipe(&final_block, sizeof(final_block));
    if (!memory.empty())
    {
        secure_wipe(memory.data(), memory.size() * sizeof(Argon2Block));
    }
    return true;
}

bool KdfParamsV2::DeriveKey(
    const std::string& passphrase,
    const uint8_t* salt,
    size_t salt_len,
    uint8_t out_key[32]) const
{
    return Argon2idHash32(
        reinterpret_cast<const uint8_t*>(passphrase.data()),
        passphrase.size(),
        salt,
        salt_len,
        m_kib,
        t,
        p,
        out_key);
}

bool XChaCha20Poly1305Seal(
    const uint8_t key[32],
    const uint8_t xnonce[24],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    std::vector<uint8_t>& out_sealed)
{
    if (key == nullptr || xnonce == nullptr || (plaintext == nullptr && plaintext_len > 0))
    {
        return false;
    }

    uint8_t subkey[32];
    hchacha20(key, xnonce, subkey);

    uint8_t inner_nonce[12];
    std::memset(inner_nonce, 0, 4u);
    std::memcpy(&inner_nonce[4], &xnonce[16], 8u);

    uint8_t block0[64];
    chacha20_block(subkey, 0u, inner_nonce, block0);

    out_sealed.resize(24u + plaintext_len + 16u);
    std::memcpy(&out_sealed[0], xnonce, 24u);

    if (plaintext_len > 0)
    {
        chacha20_xor(subkey, 1u, inner_nonce, plaintext, plaintext_len, &out_sealed[24]);
    }

    poly1305_aead_tag(
        block0,
        aad,
        aad_len,
        &out_sealed[24],
        plaintext_len,
        &out_sealed[24u + plaintext_len]);

    secure_wipe(subkey, sizeof(subkey));
    secure_wipe(block0, sizeof(block0));
    return true;
}

bool XChaCha20Poly1305Open(
    const uint8_t key[32],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* sealed,
    size_t sealed_len,
    std::vector<uint8_t>& out_plaintext)
{
    if (key == nullptr || sealed == nullptr || sealed_len < 40u)
    {
        return false;
    }

    const uint8_t* xnonce = &sealed[0];
    size_t ct_len = sealed_len - 40u;
    const uint8_t* ct = &sealed[24];
    const uint8_t* tag = &sealed[24u + ct_len];

    uint8_t subkey[32];
    hchacha20(key, xnonce, subkey);

    uint8_t inner_nonce[12];
    std::memset(inner_nonce, 0, 4u);
    std::memcpy(&inner_nonce[4], &xnonce[16], 8u);

    uint8_t block0[64];
    chacha20_block(subkey, 0u, inner_nonce, block0);

    uint8_t expected_tag[16];
    poly1305_aead_tag(block0, aad, aad_len, ct, ct_len, expected_tag);

    uint8_t diff = 0u;
    for (size_t i = 0; i < 16u; ++i)
    {
        diff |= static_cast<uint8_t>(expected_tag[i] ^ tag[i]);
    }

    if (diff != 0u)
    {
        secure_wipe(subkey, sizeof(subkey));
        secure_wipe(block0, sizeof(block0));
        secure_wipe(expected_tag, sizeof(expected_tag));
        out_plaintext.clear();
        return false;
    }

    out_plaintext.resize(ct_len);
    if (ct_len > 0)
    {
        chacha20_xor(subkey, 1u, inner_nonce, ct, ct_len, out_plaintext.data());
    }

    secure_wipe(subkey, sizeof(subkey));
    secure_wipe(block0, sizeof(block0));
    secure_wipe(expected_tag, sizeof(expected_tag));
    return true;
}

std::vector<uint8_t> BuildMasterKeyAadV2(
    const KdfParamsV2& params,
    const uint8_t* salt,
    size_t salt_len)
{
    static const char PREFIX[] = "encrypted_master_key"; // 20 bytes
    std::vector<uint8_t> encoded_params = params.Encode();
    std::vector<uint8_t> aad;
    aad.reserve(20u + encoded_params.size() + salt_len);
    aad.insert(aad.end(), reinterpret_cast<const uint8_t*>(PREFIX), reinterpret_cast<const uint8_t*>(PREFIX) + 20u);
    aad.insert(aad.end(), encoded_params.begin(), encoded_params.end());
    if (salt != nullptr && salt_len > 0)
    {
        aad.insert(aad.end(), salt, salt + salt_len);
    }
    return aad;
}

std::vector<uint8_t> BuildCkeyRecordAad(const uint8_t* pubkey, size_t pubkey_len)
{
    static const char PREFIX[] = "ckey";
    std::vector<uint8_t> aad;
    aad.reserve(4u + pubkey_len);
    aad.insert(aad.end(), reinterpret_cast<const uint8_t*>(PREFIX), reinterpret_cast<const uint8_t*>(PREFIX) + 4u);
    if (pubkey != nullptr && pubkey_len > 0)
    {
        aad.insert(aad.end(), pubkey, pubkey + pubkey_len);
    }
    return aad;
}

std::vector<uint8_t> BuildChdchainRecordAad()
{
    static const char KEY[] = "chdchain";
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(KEY), reinterpret_cast<const uint8_t*>(KEY) + 8u);
}

bool SealMasterKeyWithNonceV2(
    const uint8_t master_key[32],
    const std::string& passphrase,
    const uint8_t* salt,
    size_t salt_len,
    const KdfParamsV2& params,
    const uint8_t xnonce[24],
    std::vector<uint8_t>& out_sealed)
{
    if (master_key == nullptr || salt == nullptr || salt_len != WALLET_CRYPTO_ARGON2_SALT_SIZE || xnonce == nullptr)
    {
        return false;
    }
    uint8_t derived_key[32];
    if (!params.DeriveKey(passphrase, salt, salt_len, derived_key))
    {
        return false;
    }
    std::vector<uint8_t> aad = BuildMasterKeyAadV2(params, salt, salt_len);
    bool ok = XChaCha20Poly1305Seal(
        derived_key,
        xnonce,
        aad.data(),
        aad.size(),
        master_key,
        32u,
        out_sealed);
    secure_wipe(derived_key, sizeof(derived_key));
    return ok && out_sealed.size() == WALLET_CRYPTO_SEALED_KEY_V2_SIZE;
}

bool OpenMasterKeyV2(
    const uint8_t* sealed,
    size_t sealed_len,
    const std::string& passphrase,
    const uint8_t* salt,
    size_t salt_len,
    const KdfParamsV2& params,
    uint8_t out_master_key[32])
{
    if (sealed == nullptr || sealed_len != WALLET_CRYPTO_SEALED_KEY_V2_SIZE ||
        salt == nullptr || salt_len != WALLET_CRYPTO_ARGON2_SALT_SIZE ||
        out_master_key == nullptr)
    {
        return false;
    }
    uint8_t derived_key[32];
    if (!params.DeriveKey(passphrase, salt, salt_len, derived_key))
    {
        return false;
    }
    std::vector<uint8_t> aad = BuildMasterKeyAadV2(params, salt, salt_len);
    std::vector<uint8_t> plain;
    bool ok = XChaCha20Poly1305Open(
        derived_key,
        aad.data(),
        aad.size(),
        sealed,
        sealed_len,
        plain);
    secure_wipe(derived_key, sizeof(derived_key));
    if (!ok || plain.size() != 32u)
    {
        if (!plain.empty())
        {
            secure_wipe(plain.data(), plain.size());
        }
        return false;
    }
    std::memcpy(out_master_key, plain.data(), 32u);
    secure_wipe(plain.data(), plain.size());
    return true;
}

bool SealRecordWithNonceV2(
    const uint8_t master_key[32],
    const uint8_t* record_key,
    size_t record_key_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t xnonce[24],
    std::vector<uint8_t>& out_sealed)
{
    return XChaCha20Poly1305Seal(
        master_key,
        xnonce,
        record_key,
        record_key_len,
        plaintext,
        plaintext_len,
        out_sealed);
}

bool OpenRecordV2(
    const uint8_t master_key[32],
    const uint8_t* record_key,
    size_t record_key_len,
    const uint8_t* sealed,
    size_t sealed_len,
    std::vector<uint8_t>& out_plaintext)
{
    return XChaCha20Poly1305Open(
        master_key,
        record_key,
        record_key_len,
        sealed,
        sealed_len,
        out_plaintext);
}

bool EncryptCMasterKeyV2(
    const uint8_t master_key[32],
    const std::string& passphrase,
    const uint8_t salt[16],
    const KdfParamsV2& params,
    const uint8_t xnonce[24],
    CMasterKey& out_cmasterkey)
{
    std::vector<uint8_t> sealed;
    if (!SealMasterKeyWithNonceV2(master_key, passphrase, salt, 16u, params, xnonce, sealed))
    {
        return false;
    }
    out_cmasterkey.vchCryptedKey = sealed;
    out_cmasterkey.vchSalt.assign(salt, salt + 16u);
    out_cmasterkey.nDerivationMethod = MASTER_KEY_DERIVATION_ARGON2ID_XCHACHA20;
    out_cmasterkey.nDeriveIterations = params.t;
    out_cmasterkey.vchOtherDerivationParameters = params.Encode();
    return true;
}

bool DecryptCMasterKeyV2(
    const CMasterKey& cmasterkey,
    const std::string& passphrase,
    uint8_t out_master_key[32])
{
    if (cmasterkey.nDerivationMethod != MASTER_KEY_DERIVATION_ARGON2ID_XCHACHA20)
    {
        return false;
    }
    KdfParamsV2 params;
    if (!KdfParamsV2::Decode(cmasterkey.vchOtherDerivationParameters, params))
    {
        return false;
    }
    return OpenMasterKeyV2(
        cmasterkey.vchCryptedKey.data(),
        cmasterkey.vchCryptedKey.size(),
        passphrase,
        cmasterkey.vchSalt.data(),
        cmasterkey.vchSalt.size(),
        params,
        out_master_key);
}

} // namespace divi_pq

extern "C" {

int divi_cpp_kdf_params_v2_encode(
    uint32_t m_kib,
    uint32_t t,
    uint32_t p,
    uint8_t out_bytes[13])
{
    if (out_bytes == nullptr)
    {
        return -1;
    }
    divi_pq::KdfParamsV2 params(m_kib, t, p);
    if (!params.IsValid())
    {
        return -2;
    }
    std::vector<uint8_t> enc = params.Encode();
    std::memcpy(out_bytes, enc.data(), 13u);
    return 0;
}

int divi_cpp_kdf_params_v2_decode(
    const uint8_t* data,
    size_t len,
    uint32_t* out_m_kib,
    uint32_t* out_t,
    uint32_t* out_p)
{
    divi_pq::KdfParamsV2 params;
    if (!divi_pq::KdfParamsV2::Decode(data, len, params))
    {
        return -1;
    }
    if (out_m_kib) *out_m_kib = params.m_kib;
    if (out_t)     *out_t     = params.t;
    if (out_p)     *out_p     = params.p;
    return 0;
}

int divi_cpp_argon2id_derive_key32(
    const uint8_t* pass,
    size_t pass_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t m_kib,
    uint32_t t,
    uint32_t p,
    uint8_t out_key[32])
{
    return divi_pq::Argon2idHash32(pass, pass_len, salt, salt_len, m_kib, t, p, out_key) ? 0 : -1;
}

int divi_cpp_seal_master_key_v2(
    const uint8_t master_key[32],
    const uint8_t* pass,
    size_t pass_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t m_kib,
    uint32_t t,
    uint32_t p,
    const uint8_t xnonce[24],
    uint8_t out_sealed[72])
{
    if (out_sealed == nullptr || (pass == nullptr && pass_len > 0))
    {
        return -1;
    }
    std::string passphrase(reinterpret_cast<const char*>(pass), pass_len);
    divi_pq::KdfParamsV2 params(m_kib, t, p);
    std::vector<uint8_t> sealed;
    if (!divi_pq::SealMasterKeyWithNonceV2(master_key, passphrase, salt, salt_len, params, xnonce, sealed))
    {
        return -1;
    }
    std::memcpy(out_sealed, sealed.data(), 72u);
    return 0;
}

int divi_cpp_open_master_key_v2(
    const uint8_t* sealed,
    size_t sealed_len,
    const uint8_t* pass,
    size_t pass_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t m_kib,
    uint32_t t,
    uint32_t p,
    uint8_t out_master_key[32])
{
    if (pass == nullptr && pass_len > 0)
    {
        return -1;
    }
    std::string passphrase(reinterpret_cast<const char*>(pass), pass_len);
    divi_pq::KdfParamsV2 params(m_kib, t, p);
    return divi_pq::OpenMasterKeyV2(sealed, sealed_len, passphrase, salt, salt_len, params, out_master_key) ? 0 : -1;
}

} // extern "C"
