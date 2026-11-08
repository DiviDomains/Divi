// Copyright (c) 2026 The DIVI Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DIVI_CRYPTER_PQ_H
#define DIVI_CRYPTER_PQ_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#if defined(__linux__) && !defined(HAVE_CONFIG_H)
#ifndef HAVE_ENDIAN_H
#define HAVE_ENDIAN_H 1
#endif
#ifndef HAVE_BYTESWAP_H
#define HAVE_BYTESWAP_H 1
#endif
#ifndef HAVE_DECL_HTOBE16
#define HAVE_DECL_HTOBE16 1
#define HAVE_DECL_HTOLE16 1
#define HAVE_DECL_BE16TOH 1
#define HAVE_DECL_LE16TOH 1
#define HAVE_DECL_HTOBE32 1
#define HAVE_DECL_HTOLE32 1
#define HAVE_DECL_BE32TOH 1
#define HAVE_DECL_LE32TOH 1
#define HAVE_DECL_HTOBE64 1
#define HAVE_DECL_HTOLE64 1
#define HAVE_DECL_BE64TOH 1
#define HAVE_DECL_LE64TOH 1
#define HAVE_DECL_BSWAP_16 1
#define HAVE_DECL_BSWAP_32 1
#define HAVE_DECL_BSWAP_64 1
#endif
#endif

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include "MasterKey.h"
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

namespace divi_pq
{

/**
 * DIP-PQ-0 (§2.2): Wallet at-rest encryption parameters for CMasterKey::nDerivationMethod = 1.
 *
 * Encodes as 13 bytes:
 *   Byte 0      : 0x02 (KdfParamsV2::VERSION)
 *   Bytes 1..5  : u32_le(m_kib) (default 65536 = 64 MiB)
 *   Bytes 5..9  : u32_le(t)     (default 3 passes)
 *   Bytes 9..13 : u32_le(p)     (default 1 lane)
 *
 * Exact bit-for-bit parity with Rust `divi_wallet::at_rest::KdfParams`.
 */
struct KdfParamsV2
{
    static const uint8_t  VERSION     = 2u;
    static const size_t   ENCODED_LEN = 13u;
    static const uint32_t MAX_M_KIB   = 4u * 1024u * 1024u; // 4 GiB

    uint32_t m_kib;
    uint32_t t;
    uint32_t p;

    KdfParamsV2()
        : m_kib(WALLET_CRYPTO_DEFAULT_ARGON2_M_KIB)
        , t(WALLET_CRYPTO_DEFAULT_ARGON2_T_COST)
        , p(WALLET_CRYPTO_DEFAULT_ARGON2_P_LANES)
    {}

    KdfParamsV2(uint32_t m_kib_in, uint32_t t_in, uint32_t p_in)
        : m_kib(m_kib_in)
        , t(t_in)
        , p(p_in)
    {}

    static KdfParamsV2 Default()
    {
        return KdfParamsV2(
            WALLET_CRYPTO_DEFAULT_ARGON2_M_KIB,
            WALLET_CRYPTO_DEFAULT_ARGON2_T_COST,
            WALLET_CRYPTO_DEFAULT_ARGON2_P_LANES);
    }

    static KdfParamsV2 TestOnlyFast()
    {
        return KdfParamsV2(8u, 1u, 1u);
    }

    bool operator==(const KdfParamsV2& other) const
    {
        return m_kib == other.m_kib && t == other.t && p == other.p;
    }

    bool operator!=(const KdfParamsV2& other) const
    {
        return !(*this == other);
    }

    bool IsValid() const;
    std::vector<uint8_t> Encode() const;
    static bool Decode(const uint8_t* data, size_t len, KdfParamsV2& out);
    static bool Decode(const std::vector<uint8_t>& data, KdfParamsV2& out);

    /**
     * Derive a 32-byte key from `passphrase` and `salt` using RFC 9106 Argon2id v0x13.
     */
    bool DeriveKey(
        const std::string& passphrase,
        const uint8_t* salt,
        size_t salt_len,
        uint8_t out_key[32]) const;
};

/**
 * Self-contained pure-integer RFC 9106 Argon2id v0x13 key derivation (32-byte tag).
 */
bool Argon2idHash32(
    const uint8_t* password,
    size_t password_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t m_kib,
    uint32_t t_cost,
    uint32_t p_lanes,
    uint8_t out_key[32]);

/**
 * Self-contained pure-integer XChaCha20-Poly1305 AEAD seal (`[xnonce (24B)] || [ciphertext] || [tag (16B)]`).
 */
bool XChaCha20Poly1305Seal(
    const uint8_t key[32],
    const uint8_t xnonce[24],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    std::vector<uint8_t>& out_sealed);

/**
 * Self-contained pure-integer XChaCha20-Poly1305 AEAD open.
 * Verifies the 16-byte Poly1305 tag in constant time before writing `out_plaintext`.
 */
bool XChaCha20Poly1305Open(
    const uint8_t key[32],
    const uint8_t* aad,
    size_t aad_len,
    const uint8_t* sealed,
    size_t sealed_len,
    std::vector<uint8_t>& out_plaintext);

/**
 * Build the 49-byte DIP-PQ-0 master-key AAD:
 * `"encrypted_master_key" (20 B) || kdf_params.Encode() (13 B) || salt (16 B)`.
 */
std::vector<uint8_t> BuildMasterKeyAadV2(
    const KdfParamsV2& params,
    const uint8_t* salt,
    size_t salt_len);

/**
 * Build the per-record AAD for a `ckey` encrypted private key record: `"ckey" || pubkey`.
 */
std::vector<uint8_t> BuildCkeyRecordAad(const uint8_t* pubkey, size_t pubkey_len);

/**
 * Build the per-record AAD for the encrypted HD chain record: `"chdchain"`.
 */
std::vector<uint8_t> BuildChdchainRecordAad();

/**
 * Seal a 32-byte wallet master key under `passphrase`, `salt` (16 bytes), `params`, and `xnonce` (24 bytes),
 * producing a 72-byte `vchCryptedKey` (`24 B` XNonce + `32 B` ciphertext + `16 B` Poly1305 tag).
 */
bool SealMasterKeyWithNonceV2(
    const uint8_t master_key[32],
    const std::string& passphrase,
    const uint8_t* salt,
    size_t salt_len,
    const KdfParamsV2& params,
    const uint8_t xnonce[24],
    std::vector<uint8_t>& out_sealed);

/**
 * Open a 72-byte sealed wallet master key under `passphrase`, `salt`, and `params`.
 * Returns `false` (WrongPassphrase) if authentication fails or decrypted size != 32.
 */
bool OpenMasterKeyV2(
    const uint8_t* sealed,
    size_t sealed_len,
    const std::string& passphrase,
    const uint8_t* salt,
    size_t salt_len,
    const KdfParamsV2& params,
    uint8_t out_master_key[32]);

/**
 * Seal a wallet secret record (`ckey`, `chdchain`, etc.) under `master_key[32]` using `record_key` as AAD.
 */
bool SealRecordWithNonceV2(
    const uint8_t master_key[32],
    const uint8_t* record_key,
    size_t record_key_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t xnonce[24],
    std::vector<uint8_t>& out_sealed);

/**
 * Open a wallet secret record (`ckey`, `chdchain`, etc.) under `master_key[32]` using `record_key` as AAD.
 */
bool OpenRecordV2(
    const uint8_t master_key[32],
    const uint8_t* record_key,
    size_t record_key_len,
    const uint8_t* sealed,
    size_t sealed_len,
    std::vector<uint8_t>& out_plaintext);

/**
 * Populate a `CMasterKey` with `nDerivationMethod = 1` (`Argon2id` + `XChaCha20-Poly1305` AEAD).
 */
bool EncryptCMasterKeyV2(
    const uint8_t master_key[32],
    const std::string& passphrase,
    const uint8_t salt[16],
    const KdfParamsV2& params,
    const uint8_t xnonce[24],
    CMasterKey& out_cmasterkey);

/**
 * Decrypt a `CMasterKey` with `nDerivationMethod = 1`.
 */
bool DecryptCMasterKeyV2(
    const CMasterKey& cmasterkey,
    const std::string& passphrase,
    uint8_t out_master_key[32]);

} // namespace divi_pq

extern "C" {

int divi_cpp_kdf_params_v2_encode(
    uint32_t m_kib,
    uint32_t t,
    uint32_t p,
    uint8_t out_bytes[13]);

int divi_cpp_kdf_params_v2_decode(
    const uint8_t* data,
    size_t len,
    uint32_t* out_m_kib,
    uint32_t* out_t,
    uint32_t* out_p);

int divi_cpp_argon2id_derive_key32(
    const uint8_t* pass,
    size_t pass_len,
    const uint8_t* salt,
    size_t salt_len,
    uint32_t m_kib,
    uint32_t t,
    uint32_t p,
    uint8_t out_key[32]);

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
    uint8_t out_sealed[72]);

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
    uint8_t out_master_key[32]);

} // extern "C"

#endif // DIVI_CRYPTER_PQ_H
