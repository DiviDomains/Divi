// Copyright (c) 2026 The Divi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "PqBlockSigning.h"
#include "script/PqStakingVaultScript.h"

#include <cstring>

namespace PqBlockSigning
{

namespace
{

static const uint8_t POS_BLOCK_PAYLOAD_DOMAIN_BYTES[POS_BLOCK_PAYLOAD_DOMAIN_LEN] = {
    'D', 'I', 'V', 'I', '-', 'P', 'O', 'S', '-',
    'B', 'L', 'O', 'C', 'K', '-', 'V', '1'
};

static const uint8_t POS_BLOCK_SIG_DOMAIN_TAG_STR[19] = {
    'D', 'i', 'v', 'i', '-', 'P', 'Q', '-',
    'B', 'l', 'o', 'c', 'k', 'S', 'i', 'g', '-', 'v', '1'
};

static const uint32_t SHA256_K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static inline uint32_t Rotr32(uint32_t x, unsigned int n)
{
    return (x >> n) | (x << (32U - n));
}

static inline uint32_t ReadBe32(const uint8_t* p)
{
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

static inline void WriteBe32(uint8_t* p, uint32_t v)
{
    p[0] = static_cast<uint8_t>((v >> 24) & 0xffU);
    p[1] = static_cast<uint8_t>((v >> 16) & 0xffU);
    p[2] = static_cast<uint8_t>((v >> 8) & 0xffU);
    p[3] = static_cast<uint8_t>(v & 0xffU);
}

static inline void WriteLe32(uint8_t* p, uint32_t v)
{
    p[0] = static_cast<uint8_t>(v & 0xffU);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xffU);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xffU);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xffU);
}

static void Sha256Compress(uint32_t h[8], const uint8_t block[64])
{
    uint32_t w[64];
    for (size_t i = 0; i < 16; ++i) {
        w[i] = ReadBe32(block + i * 4);
    }
    for (size_t i = 16; i < 64; ++i) {
        uint32_t s0 = Rotr32(w[i - 15], 7) ^ Rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = Rotr32(w[i - 2], 17) ^ Rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    uint32_t a = h[0];
    uint32_t b = h[1];
    uint32_t c = h[2];
    uint32_t d = h[3];
    uint32_t e = h[4];
    uint32_t f = h[5];
    uint32_t g = h[6];
    uint32_t hh = h[7];

    for (size_t i = 0; i < 64; ++i) {
        uint32_t S1 = Rotr32(e, 6) ^ Rotr32(e, 11) ^ Rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = hh + S1 + ch + SHA256_K[i] + w[i];
        uint32_t S0 = Rotr32(a, 2) ^ Rotr32(a, 13) ^ Rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        hh = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
    h[5] += f;
    h[6] += g;
    h[7] += hh;
}

static void Sha256OneShot85(const uint8_t data85[85], uint8_t out32[32])
{
    uint32_t h[8] = {
        0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
        0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
    };
    Sha256Compress(h, data85);

    uint8_t buf[64];
    std::memset(buf, 0, sizeof(buf));
    std::memcpy(buf, data85 + 64, 21);
    buf[21] = 0x80U;
    uint64_t bitLen = 85ULL * 8ULL;
    for (size_t i = 0; i < 8; ++i) {
        buf[56 + i] = static_cast<uint8_t>((bitLen >> (56U - 8U * i)) & 0xffU);
    }
    Sha256Compress(h, buf);
    for (size_t i = 0; i < 8; ++i) {
        WriteBe32(out32 + i * 4, h[i]);
    }
}

static bool IsKnownPqSchemeId(uint8_t schemeId)
{
    return divi_pq_scheme_is_valid(schemeId) != 0;
}

static PqBlockSigErrorCode MapPqErrorToBlockSigError(int err)
{
    if (err == DIVI_PQ_OK) {
        return PqBlockSigErrorCode::Ok;
    }
    if (err == DIVI_PQ_ERR_UNKNOWN_SCHEME_ID) {
        return PqBlockSigErrorCode::UnknownSchemeId;
    }
    if (err == DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN) {
        return PqBlockSigErrorCode::SchemeForbiddenInDomain;
    }
    return PqBlockSigErrorCode::CryptoValidationError;
}

static bool EqualHash32(const uint8_t a[32], const uint8_t b[32])
{
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

} // namespace

PqBlockSigEnvelope::PqBlockSigEnvelope()
    : schemeId(DIVI_PQ_SCHEME_FNDSA512)
{
}

PqBlockSigErrorCode PqBlockSigEnvelope::ExpectedEnvelopeLen(uint8_t schemeId, size_t& outLen)
{
    outLen = 0;
    if (!IsKnownPqSchemeId(schemeId)) {
        return PqBlockSigErrorCode::UnknownSchemeId;
    }
    if (divi_pq_scheme_allowed_in_domain(
            schemeId,
            reinterpret_cast<const char*>(POS_BLOCK_SIG_DOMAIN_TAG_STR),
            sizeof(POS_BLOCK_SIG_DOMAIN_TAG_STR)) != DIVI_PQ_OK) {
        return PqBlockSigErrorCode::SchemeForbiddenInDomain;
    }
    outLen = PQ_BLOCK_SIG_HEADER_LEN +
             divi_pq_scheme_pubkey_len(schemeId) +
             divi_pq_scheme_sig_len(schemeId);
    return PqBlockSigErrorCode::Ok;
}

PqBlockSigErrorCode PqBlockSigEnvelope::Create(
    uint8_t schemeId,
    const std::vector<uint8_t>& pubkeyBytes,
    const std::vector<uint8_t>& signatureBytes,
    PqBlockSigEnvelope& outEnvelope,
    int* outPqError)
{
    if (outPqError != nullptr) {
        *outPqError = DIVI_PQ_OK;
    }
    if (!IsKnownPqSchemeId(schemeId)) {
        if (outPqError != nullptr) {
            *outPqError = DIVI_PQ_ERR_UNKNOWN_SCHEME_ID;
        }
        return PqBlockSigErrorCode::UnknownSchemeId;
    }
    if (divi_pq_scheme_allowed_in_domain(
            schemeId,
            reinterpret_cast<const char*>(POS_BLOCK_SIG_DOMAIN_TAG_STR),
            sizeof(POS_BLOCK_SIG_DOMAIN_TAG_STR)) != DIVI_PQ_OK) {
        if (outPqError != nullptr) {
            *outPqError = DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN;
        }
        return PqBlockSigErrorCode::SchemeForbiddenInDomain;
    }

    int pkErr = divi_pq_validate_pubkey_encoding(
        schemeId,
        pubkeyBytes.empty() ? nullptr : pubkeyBytes.data(),
        pubkeyBytes.size());
    if (pkErr != DIVI_PQ_OK) {
        if (outPqError != nullptr) {
            *outPqError = pkErr;
        }
        return MapPqErrorToBlockSigError(pkErr);
    }

    int sigErr = divi_pq_validate_sig_encoding(
        schemeId,
        signatureBytes.empty() ? nullptr : signatureBytes.data(),
        signatureBytes.size());
    if (sigErr != DIVI_PQ_OK) {
        if (outPqError != nullptr) {
            *outPqError = sigErr;
        }
        return MapPqErrorToBlockSigError(sigErr);
    }

    outEnvelope.schemeId = schemeId;
    outEnvelope.pubkeyBytes = pubkeyBytes;
    outEnvelope.signatureBytes = signatureBytes;
    return PqBlockSigErrorCode::Ok;
}

std::vector<uint8_t> PqBlockSigEnvelope::Encode() const
{
    std::vector<uint8_t> out;
    out.reserve(PQ_BLOCK_SIG_HEADER_LEN + pubkeyBytes.size() + signatureBytes.size());
    out.push_back(PQ_BLOCK_SIG_MAGIC);
    out.push_back(PQ_BLOCK_SIG_VERSION_V1);
    out.push_back(schemeId);
    out.insert(out.end(), pubkeyBytes.begin(), pubkeyBytes.end());
    out.insert(out.end(), signatureBytes.begin(), signatureBytes.end());
    return out;
}

PqBlockSigErrorCode PqBlockSigEnvelope::Decode(
    const uint8_t* bytes,
    size_t len,
    PqBlockSigEnvelope& outEnvelope,
    int* outPqError)
{
    if (outPqError != nullptr) {
        *outPqError = DIVI_PQ_OK;
    }
    if (bytes == nullptr || len == 0) {
        return PqBlockSigErrorCode::EmptyBlockSignature;
    }
    if (bytes[0] != PQ_BLOCK_SIG_MAGIC) {
        return PqBlockSigErrorCode::InvalidEnvelopeMagic;
    }
    if (len < PQ_BLOCK_SIG_HEADER_LEN) {
        return PqBlockSigErrorCode::InvalidEnvelopeLength;
    }
    if (bytes[1] != PQ_BLOCK_SIG_VERSION_V1) {
        return PqBlockSigErrorCode::UnsupportedEnvelopeVersion;
    }

    const uint8_t schemeId = bytes[2];
    size_t expectedLen = 0;
    PqBlockSigErrorCode lenErr = ExpectedEnvelopeLen(schemeId, expectedLen);
    if (lenErr != PqBlockSigErrorCode::Ok) {
        if (outPqError != nullptr) {
            *outPqError = (lenErr == PqBlockSigErrorCode::UnknownSchemeId)
                ? DIVI_PQ_ERR_UNKNOWN_SCHEME_ID
                : DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN;
        }
        return lenErr;
    }
    if (len != expectedLen) {
        return PqBlockSigErrorCode::InvalidEnvelopeLength;
    }

    const size_t pkLen = divi_pq_scheme_pubkey_len(schemeId);
    const size_t pkEnd = PQ_BLOCK_SIG_HEADER_LEN + pkLen;
    std::vector<uint8_t> pk(bytes + PQ_BLOCK_SIG_HEADER_LEN, bytes + pkEnd);
    std::vector<uint8_t> sig(bytes + pkEnd, bytes + expectedLen);
    return Create(schemeId, pk, sig, outEnvelope, outPqError);
}

PqBlockSigErrorCode PqBlockSigEnvelope::Decode(
    const std::vector<uint8_t>& bytes,
    PqBlockSigEnvelope& outEnvelope,
    int* outPqError)
{
    return Decode(bytes.empty() ? nullptr : bytes.data(), bytes.size(), outEnvelope, outPqError);
}

void PqBlockSigEnvelope::StakerKeyHash256(uint8_t outHash32[32]) const
{
    divi_pq_address_key_hash_256(
        schemeId,
        pubkeyBytes.empty() ? nullptr : pubkeyBytes.data(),
        pubkeyBytes.size(),
        outHash32);
}

void PqBlockSigEnvelope::SigningKeyHash256(uint8_t outHash32[32]) const
{
    divi_pq_key_hash_256(
        schemeId,
        pubkeyBytes.empty() ? nullptr : pubkeyBytes.data(),
        pubkeyBytes.size(),
        outHash32);
}

PqBlockSigErrorCode PqBlockSigEnvelope::VerifyStructuralAndStakerBinding(
    const std::vector<uint8_t>& coinstakeScriptPubKey,
    CoinstakeStakerBinding& outBinding,
    int* outPqError) const
{
    if (outPqError != nullptr) {
        *outPqError = DIVI_PQ_OK;
    }
    if (!IsKnownPqSchemeId(schemeId)) {
        if (outPqError != nullptr) {
            *outPqError = DIVI_PQ_ERR_UNKNOWN_SCHEME_ID;
        }
        return PqBlockSigErrorCode::UnknownSchemeId;
    }
    if (divi_pq_scheme_allowed_in_domain(
            schemeId,
            reinterpret_cast<const char*>(POS_BLOCK_SIG_DOMAIN_TAG_STR),
            sizeof(POS_BLOCK_SIG_DOMAIN_TAG_STR)) != DIVI_PQ_OK) {
        if (outPqError != nullptr) {
            *outPqError = DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN;
        }
        return PqBlockSigErrorCode::SchemeForbiddenInDomain;
    }

    int pkErr = divi_pq_validate_pubkey_encoding(
        schemeId,
        pubkeyBytes.empty() ? nullptr : pubkeyBytes.data(),
        pubkeyBytes.size());
    if (pkErr != DIVI_PQ_OK) {
        if (outPqError != nullptr) {
            *outPqError = pkErr;
        }
        return MapPqErrorToBlockSigError(pkErr);
    }

    int sigErr = divi_pq_validate_sig_encoding(
        schemeId,
        signatureBytes.empty() ? nullptr : signatureBytes.data(),
        signatureBytes.size());
    if (sigErr != DIVI_PQ_OK) {
        if (outPqError != nullptr) {
            *outPqError = sigErr;
        }
        return MapPqErrorToBlockSigError(sigErr);
    }

    if (!ParsePqCoinstakeScript(coinstakeScriptPubKey, outBinding)) {
        return PqBlockSigErrorCode::UnsupportedCoinstakeScriptForPqBlockSig;
    }

    uint8_t actualHash[32];
    StakerKeyHash256(actualHash);

    if (outBinding.kind == CoinstakeBindingKind::PqStakingVault) {
        // Check cold ownerHash256 FIRST so neither the cold owner key nor a degenerate
        // ownerHash256 == vaultHash256 vault can ever sign PoS blocks.
        if (EqualHash32(actualHash, outBinding.ownerHash256)) {
            return PqBlockSigErrorCode::ColdOwnerKeyForbiddenForBlockSigning;
        }
        if (!EqualHash32(actualHash, outBinding.vaultHash256)) {
            return PqBlockSigErrorCode::StakerKeyHashMismatch;
        }
        return PqBlockSigErrorCode::Ok;
    }

    if (!EqualHash32(actualHash, outBinding.addrKeyHash256)) {
        return PqBlockSigErrorCode::StakerKeyHashMismatch;
    }
    return PqBlockSigErrorCode::Ok;
}

PosBlockAuthPolicy::PosBlockAuthPolicy()
    : stage(PosBlockPolicyStage::ClassicalOnly),
      cutoffBlockTime(0)
{
    std::memset(networkMagic, 0, sizeof(networkMagic));
}

PosBlockAuthPolicy PosBlockAuthPolicy::ClassicalOnly()
{
    return PosBlockAuthPolicy();
}

PosBlockAuthPolicy PosBlockAuthPolicy::DualAllowed(const uint8_t magic4[4])
{
    PosBlockAuthPolicy p;
    p.stage = PosBlockPolicyStage::DualAllowed;
    std::memcpy(p.networkMagic, magic4, 4);
    p.cutoffBlockTime = 0;
    return p;
}

PosBlockAuthPolicy PosBlockAuthPolicy::PqRequiredForPqOutputs(const uint8_t magic4[4])
{
    PosBlockAuthPolicy p;
    p.stage = PosBlockPolicyStage::PqRequiredForPqOutputs;
    std::memcpy(p.networkMagic, magic4, 4);
    p.cutoffBlockTime = 0;
    return p;
}

PosBlockAuthPolicy PosBlockAuthPolicy::PqRequiredAllAfter(const uint8_t magic4[4], uint32_t cutoffTime)
{
    PosBlockAuthPolicy p;
    p.stage = PosBlockPolicyStage::PqRequiredAllAfter;
    std::memcpy(p.networkMagic, magic4, 4);
    p.cutoffBlockTime = cutoffTime;
    return p;
}

bool ParsePqCoinstakeScript(
    const std::vector<uint8_t>& scriptPubKey,
    CoinstakeStakerBinding& outBinding)
{
    std::memset(outBinding.ownerHash256, 0, 32);
    std::memset(outBinding.vaultHash256, 0, 32);
    std::memset(outBinding.addrKeyHash256, 0, 32);

    if (IsP2pqpkhScript(scriptPubKey, outBinding.addrKeyHash256)) {
        outBinding.kind = CoinstakeBindingKind::P2PqPkh;
        return true;
    }
    if (IsPqStakingVaultScript(scriptPubKey, outBinding.ownerHash256, outBinding.vaultHash256)) {
        outBinding.kind = CoinstakeBindingKind::PqStakingVault;
        return true;
    }
    return false;
}

bool IsClassicalCoinstakeScript(const std::vector<uint8_t>& scriptPubKey)
{
    const size_t len = scriptPubKey.size();
    if (len == 25) {
        return scriptPubKey[0] == 0x76U &&
               scriptPubKey[1] == 0xa9U &&
               scriptPubKey[2] == 0x14U &&
               scriptPubKey[23] == 0x88U &&
               scriptPubKey[24] == 0xacU;
    }
    if (len == 50) {
        return scriptPubKey[0] == 0x63U &&
               scriptPubKey[1] == 0x14U &&
               scriptPubKey[22] == 0x67U &&
               scriptPubKey[23] == 0xb9U &&
               scriptPubKey[24] == 0x14U &&
               scriptPubKey[45] == 0x68U &&
               scriptPubKey[46] == 0x78U &&
               scriptPubKey[47] == 0xa9U &&
               scriptPubKey[48] == 0x88U &&
               scriptPubKey[49] == 0xacU;
    }
    if (len == 35) {
        return scriptPubKey[0] == 0x21U &&
               (scriptPubKey[1] == 0x02U || scriptPubKey[1] == 0x03U) &&
               scriptPubKey[34] == 0xacU;
    }
    if (len == 67) {
        return scriptPubKey[0] == 0x41U &&
               scriptPubKey[1] == 0x04U &&
               scriptPubKey[66] == 0xacU;
    }
    return false;
}

PqBlockSigErrorCode ClassifyBlockSigFormat(
    const std::vector<uint8_t>& vchBlockSig,
    BlockSigFormat& outFormat,
    int* outPqError)
{
    if (outPqError != nullptr) {
        *outPqError = DIVI_PQ_OK;
    }
    if (vchBlockSig.empty()) {
        return PqBlockSigErrorCode::EmptyBlockSignature;
    }
    if (vchBlockSig[0] == PQ_BLOCK_SIG_MAGIC) {
        PqBlockSigEnvelope env;
        PqBlockSigErrorCode err = PqBlockSigEnvelope::Decode(vchBlockSig, env, outPqError);
        if (err != PqBlockSigErrorCode::Ok) {
            return err;
        }
        outFormat.kind = BlockSigFormatKind::PostQuantumV1;
        outFormat.pqEnvelope = env;
        return PqBlockSigErrorCode::Ok;
    }

    const uint8_t first = vchBlockSig[0];
    const size_t len = vchBlockSig.size();
    const bool isCompactSecp = (len == CLASSICAL_COMPACT_BLOCK_SIG_LEN) &&
                               (first >= 0x1bU && first <= 0x22U);
    const bool isDerSecp = (first == 0x30U) && (len >= 64 && len <= 73);
    if (isCompactSecp || isDerSecp) {
        outFormat.kind = BlockSigFormatKind::ClassicalSecp256k1;
        return PqBlockSigErrorCode::Ok;
    }
    if (len == FN_DSA_512_BLOCK_SIG_ENVELOPE_LEN || len == ML_DSA_44_BLOCK_SIG_ENVELOPE_LEN) {
        return PqBlockSigErrorCode::InvalidEnvelopeMagic;
    }
    return PqBlockSigErrorCode::InvalidClassicalSignatureFormat;
}

void SerializePosBlockPayloadPreimage(
    const uint8_t blockHash32[32],
    const uint8_t coinstakeTxid32[32],
    uint32_t coinstakeVout,
    uint8_t outPreimage85[POS_BLOCK_PAYLOAD_PREIMAGE_LEN])
{
    std::memcpy(outPreimage85, POS_BLOCK_PAYLOAD_DOMAIN_BYTES, POS_BLOCK_PAYLOAD_DOMAIN_LEN);
    std::memcpy(outPreimage85 + 17, blockHash32, 32);
    std::memcpy(outPreimage85 + 49, coinstakeTxid32, 32);
    WriteLe32(outPreimage85 + 81, coinstakeVout);
}

void ComputePosBlockPayloadHash(
    const uint8_t blockHash32[32],
    const uint8_t coinstakeTxid32[32],
    uint32_t coinstakeVout,
    uint8_t outPayloadHash32[32])
{
    uint8_t preimage[POS_BLOCK_PAYLOAD_PREIMAGE_LEN];
    SerializePosBlockPayloadPreimage(blockHash32, coinstakeTxid32, coinstakeVout, preimage);
    Sha256OneShot85(preimage, outPayloadHash32);
}

PqBlockSigErrorCode ComputePosBlockSigningPrehash(
    const uint8_t networkMagic4[4],
    uint8_t schemeId,
    const uint8_t* pubkeyBytes,
    size_t pubkeyLen,
    const uint8_t blockHash32[32],
    const uint8_t coinstakeTxid32[32],
    uint32_t coinstakeVout,
    uint8_t outPrehash64[64],
    int* outPqError)
{
    if (outPqError != nullptr) {
        *outPqError = DIVI_PQ_OK;
    }
    if (!IsKnownPqSchemeId(schemeId)) {
        if (outPqError != nullptr) {
            *outPqError = DIVI_PQ_ERR_UNKNOWN_SCHEME_ID;
        }
        return PqBlockSigErrorCode::UnknownSchemeId;
    }
    if (divi_pq_scheme_allowed_in_domain(
            schemeId,
            reinterpret_cast<const char*>(POS_BLOCK_SIG_DOMAIN_TAG_STR),
            sizeof(POS_BLOCK_SIG_DOMAIN_TAG_STR)) != DIVI_PQ_OK) {
        if (outPqError != nullptr) {
            *outPqError = DIVI_PQ_ERR_SCHEME_FORBIDDEN_IN_DOMAIN;
        }
        return PqBlockSigErrorCode::SchemeForbiddenInDomain;
    }

    int pkErr = divi_pq_validate_pubkey_encoding(schemeId, pubkeyBytes, pubkeyLen);
    if (pkErr != DIVI_PQ_OK) {
        if (outPqError != nullptr) {
            *outPqError = pkErr;
        }
        return MapPqErrorToBlockSigError(pkErr);
    }

    uint8_t payloadHash32[32];
    ComputePosBlockPayloadHash(blockHash32, coinstakeTxid32, coinstakeVout, payloadHash32);

    uint8_t pkHash32[32];
    divi_pq_key_hash_256(schemeId, pubkeyBytes, pubkeyLen, pkHash32);

    divi_pq_signing_prehash(
        reinterpret_cast<const char*>(POS_BLOCK_SIG_DOMAIN_TAG_STR),
        sizeof(POS_BLOCK_SIG_DOMAIN_TAG_STR),
        networkMagic4,
        schemeId,
        pkHash32,
        payloadHash32,
        outPrehash64);
    return PqBlockSigErrorCode::Ok;
}

static PqBlockSigErrorCode VerifyDualOrPqOutputPolicy(
    const BlockSigFormat& format,
    const std::vector<uint8_t>& coinstakeScriptPubKey,
    const uint8_t blockHash32[32],
    const uint8_t coinstakeTxid32[32],
    uint32_t coinstakeVout,
    const uint8_t networkMagic4[4],
    VerifiedBlockSigBinding& outVerified,
    int* outPqError)
{
    CoinstakeStakerBinding tmpBinding;
    const bool isPqOutput = ParsePqCoinstakeScript(coinstakeScriptPubKey, tmpBinding);

    if (format.kind == BlockSigFormatKind::ClassicalSecp256k1) {
        if (isPqOutput) {
            return PqBlockSigErrorCode::MissingPostQuantumBlockSigForPqOutput;
        }
        if (!IsClassicalCoinstakeScript(coinstakeScriptPubKey)) {
            return PqBlockSigErrorCode::UnsupportedCoinstakeScriptForClassicalBlockSig;
        }
        outVerified.kind = BlockSigFormatKind::ClassicalSecp256k1;
        return PqBlockSigErrorCode::Ok;
    }

    CoinstakeStakerBinding binding;
    PqBlockSigErrorCode bindErr = format.pqEnvelope.VerifyStructuralAndStakerBinding(
        coinstakeScriptPubKey,
        binding,
        outPqError);
    if (bindErr != PqBlockSigErrorCode::Ok) {
        return bindErr;
    }

    outVerified.kind = BlockSigFormatKind::PostQuantumV1;
    outVerified.schemeId = format.pqEnvelope.schemeId;
    format.pqEnvelope.StakerKeyHash256(outVerified.stakerKeyHash256);
    outVerified.coinstakeBinding = binding;
    ComputePosBlockPayloadHash(blockHash32, coinstakeTxid32, coinstakeVout, outVerified.payloadHash256);

    return ComputePosBlockSigningPrehash(
        networkMagic4,
        format.pqEnvelope.schemeId,
        format.pqEnvelope.pubkeyBytes.data(),
        format.pqEnvelope.pubkeyBytes.size(),
        blockHash32,
        coinstakeTxid32,
        coinstakeVout,
        outVerified.signingPrehash512,
        outPqError);
}

PqBlockSigErrorCode VerifyBlockSigEnvelopeBinding(
    const std::vector<uint8_t>& vchBlockSig,
    const std::vector<uint8_t>& coinstakeScriptPubKey,
    const uint8_t blockHash32[32],
    const uint8_t coinstakeTxid32[32],
    uint32_t coinstakeVout,
    uint32_t blockTime,
    const PosBlockAuthPolicy& policy,
    VerifiedBlockSigBinding& outVerified,
    int* outPqError)
{
    std::memset(&outVerified, 0, sizeof(outVerified));
    BlockSigFormat format;
    PqBlockSigErrorCode fmtErr = ClassifyBlockSigFormat(vchBlockSig, format, outPqError);
    if (fmtErr != PqBlockSigErrorCode::Ok) {
        return fmtErr;
    }

    CoinstakeStakerBinding tmpBinding;
    const bool isPqOutput = ParsePqCoinstakeScript(coinstakeScriptPubKey, tmpBinding);

    if (policy.stage == PosBlockPolicyStage::ClassicalOnly) {
        if (format.kind == BlockSigFormatKind::PostQuantumV1) {
            return PqBlockSigErrorCode::PostQuantumBlockSigForbiddenBeforeActivation;
        }
        if (isPqOutput || !IsClassicalCoinstakeScript(coinstakeScriptPubKey)) {
            return PqBlockSigErrorCode::UnsupportedCoinstakeScriptForClassicalBlockSig;
        }
        outVerified.kind = BlockSigFormatKind::ClassicalSecp256k1;
        return PqBlockSigErrorCode::Ok;
    }

    if (policy.stage == PosBlockPolicyStage::PqRequiredAllAfter) {
        if (blockTime >= policy.cutoffBlockTime &&
            format.kind == BlockSigFormatKind::ClassicalSecp256k1) {
            return PqBlockSigErrorCode::MissingPostQuantumBlockSigAfterCutoff;
        }
    }

    return VerifyDualOrPqOutputPolicy(
        format,
        coinstakeScriptPubKey,
        blockHash32,
        coinstakeTxid32,
        coinstakeVout,
        policy.networkMagic,
        outVerified,
        outPqError);
}

} // namespace PqBlockSigning

extern "C" {

void divi_cpp_pos_block_payload_hash(
    const uint8_t block_hash32[32],
    const uint8_t coinstake_txid32[32],
    uint32_t coinstake_vout,
    uint8_t out_payload_hash32[32])
{
    PqBlockSigning::ComputePosBlockPayloadHash(
        block_hash32,
        coinstake_txid32,
        coinstake_vout,
        out_payload_hash32);
}

int divi_cpp_pos_block_signing_prehash(
    const uint8_t network_magic4[4],
    uint8_t scheme_id,
    const uint8_t* pubkey_ptr,
    size_t pubkey_len,
    const uint8_t block_hash32[32],
    const uint8_t coinstake_txid32[32],
    uint32_t coinstake_vout,
    uint8_t out_prehash64[64])
{
    PqBlockSigning::PqBlockSigErrorCode err = PqBlockSigning::ComputePosBlockSigningPrehash(
        network_magic4,
        scheme_id,
        pubkey_ptr,
        pubkey_len,
        block_hash32,
        coinstake_txid32,
        coinstake_vout,
        out_prehash64,
        nullptr);
    return static_cast<int>(err);
}

int divi_cpp_verify_block_sig_envelope_binding(
    const uint8_t* vch_block_sig_ptr,
    size_t vch_block_sig_len,
    const uint8_t* coinstake_script_ptr,
    size_t coinstake_script_len,
    const uint8_t block_hash32[32],
    const uint8_t coinstake_txid32[32],
    uint32_t coinstake_vout,
    uint32_t block_time,
    uint8_t policy_stage,
    const uint8_t network_magic4[4],
    uint32_t cutoff_block_time,
    uint8_t* out_format_kind,
    uint8_t* out_scheme_id,
    uint8_t out_staker_key_hash32[32],
    uint8_t out_payload_hash32[32],
    uint8_t out_signing_prehash64[64])
{
    std::vector<uint8_t> sigVec;
    if (vch_block_sig_ptr != nullptr && vch_block_sig_len > 0) {
        sigVec.assign(vch_block_sig_ptr, vch_block_sig_ptr + vch_block_sig_len);
    }
    std::vector<uint8_t> scriptVec;
    if (coinstake_script_ptr != nullptr && coinstake_script_len > 0) {
        scriptVec.assign(coinstake_script_ptr, coinstake_script_ptr + coinstake_script_len);
    }

    PqBlockSigning::PosBlockAuthPolicy policy;
    if (policy_stage == 0) {
        policy = PqBlockSigning::PosBlockAuthPolicy::ClassicalOnly();
    } else if (policy_stage == 1) {
        policy = PqBlockSigning::PosBlockAuthPolicy::DualAllowed(network_magic4);
    } else if (policy_stage == 2) {
        policy = PqBlockSigning::PosBlockAuthPolicy::PqRequiredForPqOutputs(network_magic4);
    } else {
        policy = PqBlockSigning::PosBlockAuthPolicy::PqRequiredAllAfter(network_magic4, cutoff_block_time);
    }

    PqBlockSigning::VerifiedBlockSigBinding verified;
    PqBlockSigning::PqBlockSigErrorCode err = PqBlockSigning::VerifyBlockSigEnvelopeBinding(
        sigVec,
        scriptVec,
        block_hash32,
        coinstake_txid32,
        coinstake_vout,
        block_time,
        policy,
        verified,
        nullptr);
    if (err == PqBlockSigning::PqBlockSigErrorCode::Ok) {
        if (out_format_kind != nullptr) {
            *out_format_kind = static_cast<uint8_t>(verified.kind);
        }
        if (out_scheme_id != nullptr) {
            *out_scheme_id = verified.schemeId;
        }
        if (out_staker_key_hash32 != nullptr) {
            std::memcpy(out_staker_key_hash32, verified.stakerKeyHash256, 32);
        }
        if (out_payload_hash32 != nullptr) {
            std::memcpy(out_payload_hash32, verified.payloadHash256, 32);
        }
        if (out_signing_prehash64 != nullptr) {
            std::memcpy(out_signing_prehash64, verified.signingPrehash512, 64);
        }
    }
    return static_cast<int>(err);
}

} // extern "C"
