#ifndef MASTER_KEY_H
#define MASTER_KEY_H
#include <vector>
#include <serialize.h>

/** Derivation method identifiers for CMasterKey::nDerivationMethod (DIP-PQ-0 §2). */
static const unsigned int MASTER_KEY_DERIVATION_LEGACY_SHA512_AES    = 0u;
static const unsigned int MASTER_KEY_DERIVATION_ARGON2ID_XCHACHA20   = 1u;
static const unsigned int WALLET_CRYPTO_ARGON2_SALT_SIZE             = 16u;
static const unsigned int WALLET_CRYPTO_KDF_PARAMS_V2_SIZE           = 13u;
static const unsigned int WALLET_CRYPTO_SEALED_KEY_V2_SIZE           = 72u;
static const unsigned int WALLET_CRYPTO_DEFAULT_ARGON2_M_KIB         = 65536u;
static const unsigned int WALLET_CRYPTO_DEFAULT_ARGON2_T_COST        = 3u;
static const unsigned int WALLET_CRYPTO_DEFAULT_ARGON2_P_LANES       = 1u;

/** Master key for wallet encryption */
class CMasterKey
{
public:
    std::vector<unsigned char> vchCryptedKey;
    std::vector<unsigned char> vchSalt;
    //! 0 = EVP_sha512() + AES-256-CBC (legacy)
    //! 1 = Argon2id(m=65536 KiB, t=3, p=1) + XChaCha20-Poly1305 AEAD (DIP-PQ-0)
    unsigned int nDerivationMethod;
    unsigned int nDeriveIterations;
    //! 13-byte KdfParamsV2 encoding (0x02 || u32_le(m_kib) || u32_le(t) || u32_le(p)) when nDerivationMethod == 1
    std::vector<unsigned char> vchOtherDerivationParameters;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion)
    {
        READWRITE(vchCryptedKey);
        READWRITE(vchSalt);
        READWRITE(nDerivationMethod);
        READWRITE(nDeriveIterations);
        READWRITE(vchOtherDerivationParameters);
    }

    CMasterKey()
    {
        // 25000 rounds is just under 0.1 seconds on a 1.86 GHz Pentium M
        // ie slightly lower than the lowest hardware we need bother supporting
        nDeriveIterations = 25000;
        nDerivationMethod = 0;
        vchOtherDerivationParameters = std::vector<unsigned char>(0);
    }
};
#endif// MASTER_KEY_H