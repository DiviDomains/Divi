// Copyright (c) 2026 The Divi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "spork_pq.h"

#include <cstring>
#include <limits>

namespace SporkPq
{

namespace
{

static const uint8_t SPORK_PQ_PAYLOAD_DOMAIN_BYTES[SPORK_PQ_PAYLOAD_DOMAIN_LEN] = {
    'D', 'I', 'V', 'I', '-', 'S', 'P', 'O', 'R', 'K', '-',
    'P', 'A', 'Y', 'L', 'O', 'A', 'D', '-', 'V', '1'
};

static const uint8_t SPORK_PQ_DOMAIN_TAG_STR[16] = {
    'D', 'i', 'v', 'i', '-', 'P', 'Q', '-', 'S', 'p', 'o', 'r', 'k', '-', 'v', '1'
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

static inline void WriteLe64(uint8_t* p, uint64_t v)
{
    for (size_t i = 0; i < 8; ++i) {
        p[i] = static_cast<uint8_t>((v >> (8U * i)) & 0xffU);
    }
}

struct Sha256Ctx {
    uint32_t h[8];
    uint8_t buf[64];
    size_t bufLen;
    uint64_t totalBytes;
};

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

static void Sha256Init(Sha256Ctx* ctx)
{
    ctx->h[0] = 0x6a09e667UL;
    ctx->h[1] = 0xbb67ae85UL;
    ctx->h[2] = 0x3c6ef372UL;
    ctx->h[3] = 0xa54ff53aUL;
    ctx->h[4] = 0x510e527fUL;
    ctx->h[5] = 0x9b05688cUL;
    ctx->h[6] = 0x1f83d9abUL;
    ctx->h[7] = 0x5be0cd19UL;
    ctx->bufLen = 0;
    ctx->totalBytes = 0;
}

static void Sha256Update(Sha256Ctx* ctx, const uint8_t* data, size_t len)
{
    ctx->totalBytes += static_cast<uint64_t>(len);
    size_t offset = 0;
    if (ctx->bufLen > 0) {
        size_t take = 64 - ctx->bufLen;
        if (take > len) {
            take = len;
        }
        std::memcpy(ctx->buf + ctx->bufLen, data, take);
        ctx->bufLen += take;
        offset += take;
        if (ctx->bufLen == 64) {
            Sha256Compress(ctx->h, ctx->buf);
            ctx->bufLen = 0;
        }
    }
    while (offset + 64 <= len) {
        Sha256Compress(ctx->h, data + offset);
        offset += 64;
    }
    if (offset < len) {
        ctx->bufLen = len - offset;
        std::memcpy(ctx->buf, data + offset, ctx->bufLen);
    }
}

static void Sha256Final(Sha256Ctx* ctx, uint8_t out32[32])
{
    uint64_t bitLen = ctx->totalBytes * 8ULL;
    ctx->buf[ctx->bufLen++] = 0x80U;
    if (ctx->bufLen > 56) {
        while (ctx->bufLen < 64) {
            ctx->buf[ctx->bufLen++] = 0;
        }
        Sha256Compress(ctx->h, ctx->buf);
        ctx->bufLen = 0;
    }
    while (ctx->bufLen < 56) {
        ctx->buf[ctx->bufLen++] = 0;
    }
    for (size_t i = 0; i < 8; ++i) {
        ctx->buf[56 + i] = static_cast<uint8_t>((bitLen >> (56U - 8U * i)) & 0xffU);
    }
    Sha256Compress(ctx->h, ctx->buf);
    for (size_t i = 0; i < 8; ++i) {
        WriteBe32(out32 + i * 4, ctx->h[i]);
    }
}

/**
 * Strictly parse a canonical base-10 signed 64-bit integer string matching Rust's
 * `if let Ok(v) = value.parse::<i64>() { if v.to_string() == value { ... } }`.
 */
static bool TryParseCanonicalI64(const std::string& s, int64_t& outVal)
{
    if (s.empty()) {
        return false;
    }
    size_t idx = 0;
    bool negative = false;
    if (s[0] == '-') {
        negative = true;
        idx = 1;
        if (s.size() == 1) {
            return false;
        }
    }
    // Reject leading zeros such as "00", "-0", "01"
    if (s[idx] == '0') {
        if (negative || s.size() != 1) {
            return false;
        }
        outVal = 0;
        return true;
    }

    uint64_t limit = negative
        ? (static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1ULL)
        : static_cast<uint64_t>(std::numeric_limits<int64_t>::max());

    uint64_t acc = 0;
    for (; idx < s.size(); ++idx) {
        char c = s[idx];
        if (c < '0' || c > '9') {
            return false;
        }
        uint64_t digit = static_cast<uint64_t>(c - '0');
        if (acc > (limit - digit) / 10ULL) {
            return false;
        }
        acc = acc * 10ULL + digit;
    }

    if (negative) {
        if (acc == static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1ULL) {
            outVal = std::numeric_limits<int64_t>::min();
        } else {
            outVal = -static_cast<int64_t>(acc);
        }
    } else {
        outVal = static_cast<int64_t>(acc);
    }
    return true;
}

} // namespace

SporkAuthPolicy::SporkAuthPolicy()
    : stage(SporkPolicyStage::ClassicalOnly),
      cutoffTimeSigned(0)
{
    std::memset(pqSporkPubkey, 0, sizeof(pqSporkPubkey));
    std::memset(networkMagic, 0, sizeof(networkMagic));
}

SporkAuthPolicy SporkAuthPolicy::ClassicalOnly()
{
    return SporkAuthPolicy();
}

SporkAuthPolicy SporkAuthPolicy::HybridOptional(
    const uint8_t pqPubkey60[PQ_LMS_SPORK_PUBKEY_LEN],
    const uint8_t magic4[4])
{
    SporkAuthPolicy policy;
    policy.stage = SporkPolicyStage::HybridOptional;
    std::memcpy(policy.pqSporkPubkey, pqPubkey60, PQ_LMS_SPORK_PUBKEY_LEN);
    std::memcpy(policy.networkMagic, magic4, 4);
    policy.cutoffTimeSigned = 0;
    return policy;
}

SporkAuthPolicy SporkAuthPolicy::HybridRequiredAfter(
    const uint8_t pqPubkey60[PQ_LMS_SPORK_PUBKEY_LEN],
    const uint8_t magic4[4],
    int64_t cutoffTime)
{
    SporkAuthPolicy policy;
    policy.stage = SporkPolicyStage::HybridRequiredAfter;
    std::memcpy(policy.pqSporkPubkey, pqPubkey60, PQ_LMS_SPORK_PUBKEY_LEN);
    std::memcpy(policy.networkMagic, magic4, 4);
    policy.cutoffTimeSigned = cutoffTime;
    return policy;
}

void ComputeSporkPqPayloadHashI64(
    int32_t sporkId,
    int64_t value,
    int64_t timeSigned,
    const uint8_t sigSecp256k1[CLASSICAL_SPORK_SIG_LEN],
    uint8_t outHash32[32])
{
    uint8_t preimage[106];
    std::memcpy(preimage, SPORK_PQ_PAYLOAD_DOMAIN_BYTES, SPORK_PQ_PAYLOAD_DOMAIN_LEN);
    WriteLe32(preimage + 21, static_cast<uint32_t>(sporkId));
    WriteLe64(preimage + 25, static_cast<uint64_t>(value));
    WriteLe64(preimage + 33, static_cast<uint64_t>(timeSigned));
    std::memcpy(preimage + 41, sigSecp256k1, CLASSICAL_SPORK_SIG_LEN);

    Sha256Ctx ctx;
    Sha256Init(&ctx);
    Sha256Update(&ctx, preimage, sizeof(preimage));
    Sha256Final(&ctx, outHash32);
}

void ComputeSporkPqPayloadHash(
    int32_t sporkId,
    const std::string& value,
    int64_t timeSigned,
    const uint8_t sigSecp256k1[CLASSICAL_SPORK_SIG_LEN],
    uint8_t outHash32[32])
{
    int64_t parsedVal = 0;
    if (TryParseCanonicalI64(value, parsedVal)) {
        ComputeSporkPqPayloadHashI64(sporkId, parsedVal, timeSigned, sigSecp256k1, outHash32);
        return;
    }

    uint8_t idLe[4];
    uint8_t lenLe[8];
    uint8_t sep = 0xffU;
    uint8_t timeLe[8];
    WriteLe32(idLe, static_cast<uint32_t>(sporkId));
    WriteLe64(lenLe, static_cast<uint64_t>(value.size()));
    WriteLe64(timeLe, static_cast<uint64_t>(timeSigned));

    Sha256Ctx ctx;
    Sha256Init(&ctx);
    Sha256Update(&ctx, SPORK_PQ_PAYLOAD_DOMAIN_BYTES, SPORK_PQ_PAYLOAD_DOMAIN_LEN);
    Sha256Update(&ctx, idLe, sizeof(idLe));
    Sha256Update(&ctx, lenLe, sizeof(lenLe));
    Sha256Update(&ctx, &sep, 1);
    if (!value.empty()) {
        Sha256Update(&ctx, reinterpret_cast<const uint8_t*>(value.data()), value.size());
    }
    Sha256Update(&ctx, timeLe, sizeof(timeLe));
    Sha256Update(&ctx, sigSecp256k1, CLASSICAL_SPORK_SIG_LEN);
    Sha256Final(&ctx, outHash32);
}

bool ComputeSporkPqSigningPrehash(
    int32_t sporkId,
    const std::string& value,
    int64_t timeSigned,
    const uint8_t sigSecp256k1[CLASSICAL_SPORK_SIG_LEN],
    const uint8_t networkMagic[4],
    const uint8_t pqSporkPubkey[PQ_LMS_SPORK_PUBKEY_LEN],
    uint8_t outPrehash64[64])
{
    uint8_t payloadHash32[32];
    ComputeSporkPqPayloadHash(sporkId, value, timeSigned, sigSecp256k1, payloadHash32);

    uint8_t pkHash32[32];
    divi_pq_key_hash_256(
        DIVI_PQ_SCHEME_LMS_SHA256_M32_H10,
        pqSporkPubkey,
        PQ_LMS_SPORK_PUBKEY_LEN,
        pkHash32);

    divi_pq_signing_prehash(
        reinterpret_cast<const char*>(SPORK_PQ_DOMAIN_TAG_STR),
        sizeof(SPORK_PQ_DOMAIN_TAG_STR),
        networkMagic,
        DIVI_PQ_SCHEME_LMS_SHA256_M32_H10,
        pkHash32,
        payloadHash32,
        outPrehash64);
    return true;
}

bool ExtractHybridSporkLmsLeafIndex(
    const std::vector<uint8_t>& vchSig,
    uint32_t& outLmsLeafQ)
{
    if (vchSig.size() != HYBRID_SPORK_SIG_LEN) {
        return false;
    }
    const uint8_t* lmsSig = vchSig.data() + CLASSICAL_SPORK_SIG_LEN;
    outLmsLeafQ = ReadBe32(lmsSig);
    return true;
}

SporkVerifyErrorCode VerifySporkWithPolicy(
    int32_t sporkId,
    const std::string& value,
    int64_t timeSigned,
    const std::vector<uint8_t>& vchSig,
    bool classicalSignatureValid,
    const SporkAuthPolicy& policy,
    SporkVerifyResult& outResult,
    int* outPqError)
{
    if (outPqError != nullptr) {
        *outPqError = DIVI_PQ_OK;
    }
    outResult.kind = SporkAuthKind::ClassicalV1;
    outResult.lmsLeafQ = 0;

    const size_t sigLen = vchSig.size();
    if (sigLen != CLASSICAL_SPORK_SIG_LEN && sigLen != HYBRID_SPORK_SIG_LEN) {
        return SporkVerifyErrorCode::InvalidSignatureLength;
    }

    const uint8_t* sigSecp256k1 = vchSig.data();
    const bool headerRangeOk = (sigSecp256k1[0] >= 31U && sigSecp256k1[0] <= 34U);
    if (!headerRangeOk || !classicalSignatureValid) {
        return SporkVerifyErrorCode::InvalidClassicalSignature;
    }

    if (sigLen == CLASSICAL_SPORK_SIG_LEN) {
        if (policy.stage == SporkPolicyStage::HybridRequiredAfter &&
            timeSigned >= policy.cutoffTimeSigned) {
            return SporkVerifyErrorCode::MissingPostQuantumSignatureAfterCutoff;
        }
        outResult.kind = SporkAuthKind::ClassicalV1;
        outResult.lmsLeafQ = 0;
        return SporkVerifyErrorCode::Ok;
    }

    const uint8_t* lmsSig = vchSig.data() + CLASSICAL_SPORK_SIG_LEN;
    if (policy.stage == SporkPolicyStage::ClassicalOnly) {
        int pqErr = divi_pq_validate_sig_encoding(
            DIVI_PQ_SCHEME_LMS_SHA256_M32_H10,
            lmsSig,
            PQ_LMS_SPORK_SIG_LEN);
        if (pqErr != DIVI_PQ_OK) {
            if (outPqError != nullptr) {
                *outPqError = pqErr;
            }
            return SporkVerifyErrorCode::InvalidPostQuantumSignature;
        }
        outResult.kind = SporkAuthKind::HybridV2;
        outResult.lmsLeafQ = ReadBe32(lmsSig);
        return SporkVerifyErrorCode::Ok;
    }

    uint8_t prehash64[64];
    if (!ComputeSporkPqSigningPrehash(
            sporkId,
            value,
            timeSigned,
            sigSecp256k1,
            policy.networkMagic,
            policy.pqSporkPubkey,
            prehash64)) {
        return SporkVerifyErrorCode::InvalidPostQuantumSignature;
    }

    int pqErr = divi_pq_lms_m32_h10_verify(
        policy.pqSporkPubkey,
        PQ_LMS_SPORK_PUBKEY_LEN,
        prehash64,
        64,
        lmsSig,
        PQ_LMS_SPORK_SIG_LEN);
    if (pqErr != DIVI_PQ_OK) {
        if (outPqError != nullptr) {
            *outPqError = pqErr;
        }
        return SporkVerifyErrorCode::InvalidPostQuantumSignature;
    }

    outResult.kind = SporkAuthKind::HybridV2;
    outResult.lmsLeafQ = ReadBe32(lmsSig);
    return SporkVerifyErrorCode::Ok;
}

SporkVerifyErrorCode verify_hybrid_spork_v2(
    int32_t sporkId,
    const std::string& value,
    int64_t timeSigned,
    const uint8_t hybridSig2577[HYBRID_SPORK_SIG_LEN],
    bool classicalSignatureValid,
    const uint8_t networkMagic[4],
    const uint8_t pqSporkPubkey[PQ_LMS_SPORK_PUBKEY_LEN],
    uint32_t& outLmsLeafQ,
    int* outPqError)
{
    std::vector<uint8_t> sigVec(hybridSig2577, hybridSig2577 + HYBRID_SPORK_SIG_LEN);
    SporkAuthPolicy policy = SporkAuthPolicy::HybridOptional(pqSporkPubkey, networkMagic);
    SporkVerifyResult res;
    SporkVerifyErrorCode code = VerifySporkWithPolicy(
        sporkId,
        value,
        timeSigned,
        sigVec,
        classicalSignatureValid,
        policy,
        res,
        outPqError);
    if (code == SporkVerifyErrorCode::Ok) {
        outLmsLeafQ = res.lmsLeafQ;
    }
    return code;
}

SporkLmsStateTracker::SporkLmsStateTracker()
    : hasLastGlobalQ_(false),
      lastGlobalQ_(0)
{
}

void SporkLmsStateTracker::Reset()
{
    hasLastGlobalQ_ = false;
    lastGlobalQ_ = 0;
    perSporkLastQ_.clear();
    observedLeafMessageHash_.clear();
}

bool SporkLmsStateTracker::HasLastGlobalLeafIndex() const
{
    return hasLastGlobalQ_;
}

uint32_t SporkLmsStateTracker::LastGlobalLeafIndex() const
{
    return lastGlobalQ_;
}

bool SporkLmsStateTracker::GetSporkLastLeafIndex(int32_t sporkId, uint32_t& outLeafQ) const
{
    std::map<int32_t, uint32_t>::const_iterator it = perSporkLastQ_.find(sporkId);
    if (it == perSporkLastQ_.end()) {
        return false;
    }
    outLeafQ = it->second;
    return true;
}

SporkVerifyErrorCode SporkLmsStateTracker::RecordVerifiedLeaf(
    int32_t sporkId,
    const uint8_t sporkMessageHash32[32],
    uint32_t lmsLeafQ,
    bool enforceStrictMonotonicPerSpork)
{
    std::vector<uint8_t> msgHash(sporkMessageHash32, sporkMessageHash32 + 32);

    std::map<uint32_t, std::vector<uint8_t> >::const_iterator leafIt =
        observedLeafMessageHash_.find(lmsLeafQ);
    if (leafIt != observedLeafMessageHash_.end()) {
        if (leafIt->second != msgHash) {
            return SporkVerifyErrorCode::LmsLeafReusedAcrossDistinctMessages;
        }
        // Exact duplicate re-broadcast of the same Spork message is idempotent
        return SporkVerifyErrorCode::Ok;
    }

    std::map<int32_t, uint32_t>::const_iterator sporkIt = perSporkLastQ_.find(sporkId);
    if (sporkIt != perSporkLastQ_.end() && enforceStrictMonotonicPerSpork) {
        if (lmsLeafQ <= sporkIt->second) {
            return SporkVerifyErrorCode::LmsLeafNonMonotonic;
        }
    }

    observedLeafMessageHash_[lmsLeafQ] = msgHash;
    perSporkLastQ_[sporkId] = lmsLeafQ;
    if (!hasLastGlobalQ_ || lmsLeafQ > lastGlobalQ_) {
        hasLastGlobalQ_ = true;
        lastGlobalQ_ = lmsLeafQ;
    }
    return SporkVerifyErrorCode::Ok;
}

} // namespace SporkPq

extern "C" {

void divi_cpp_spork_pq_payload_hash_i64(
    int32_t spork_id,
    int64_t value,
    int64_t time_signed,
    const uint8_t sig_secp256k1[65],
    uint8_t out_hash32[32])
{
    SporkPq::ComputeSporkPqPayloadHashI64(spork_id, value, time_signed, sig_secp256k1, out_hash32);
}

void divi_cpp_spork_pq_payload_hash_str(
    int32_t spork_id,
    const uint8_t* value_ptr,
    size_t value_len,
    int64_t time_signed,
    const uint8_t sig_secp256k1[65],
    uint8_t out_hash32[32])
{
    std::string val(
        reinterpret_cast<const char*>(value_ptr),
        value_ptr != nullptr ? value_len : 0);
    SporkPq::ComputeSporkPqPayloadHash(spork_id, val, time_signed, sig_secp256k1, out_hash32);
}

int divi_cpp_spork_pq_signing_prehash(
    int32_t spork_id,
    const uint8_t* value_ptr,
    size_t value_len,
    int64_t time_signed,
    const uint8_t sig_secp256k1[65],
    const uint8_t network_magic[4],
    const uint8_t pq_spork_pubkey[60],
    uint8_t out_prehash64[64])
{
    std::string val(
        reinterpret_cast<const char*>(value_ptr),
        value_ptr != nullptr ? value_len : 0);
    bool ok = SporkPq::ComputeSporkPqSigningPrehash(
        spork_id,
        val,
        time_signed,
        sig_secp256k1,
        network_magic,
        pq_spork_pubkey,
        out_prehash64);
    return ok ? 0 : -1;
}

int divi_cpp_verify_spork_with_policy(
    int32_t spork_id,
    const uint8_t* value_ptr,
    size_t value_len,
    int64_t time_signed,
    const uint8_t* sig_ptr,
    size_t sig_len,
    int classical_sig_valid,
    uint8_t policy_stage,
    const uint8_t pq_spork_pubkey[60],
    const uint8_t network_magic[4],
    int64_t cutoff_time_signed,
    uint8_t* out_auth_kind,
    uint32_t* out_lms_leaf_q)
{
    std::string val(
        reinterpret_cast<const char*>(value_ptr),
        value_ptr != nullptr ? value_len : 0);
    std::vector<uint8_t> sigVec;
    if (sig_ptr != nullptr && sig_len > 0) {
        sigVec.assign(sig_ptr, sig_ptr + sig_len);
    }

    SporkPq::SporkAuthPolicy policy;
    if (policy_stage == 0) {
        policy = SporkPq::SporkAuthPolicy::ClassicalOnly();
    } else if (policy_stage == 1) {
        policy = SporkPq::SporkAuthPolicy::HybridOptional(pq_spork_pubkey, network_magic);
    } else {
        policy = SporkPq::SporkAuthPolicy::HybridRequiredAfter(
            pq_spork_pubkey,
            network_magic,
            cutoff_time_signed);
    }

    SporkPq::SporkVerifyResult res;
    SporkPq::SporkVerifyErrorCode code = SporkPq::VerifySporkWithPolicy(
        spork_id,
        val,
        time_signed,
        sigVec,
        classical_sig_valid != 0,
        policy,
        res,
        nullptr);
    if (out_auth_kind != nullptr) {
        *out_auth_kind = static_cast<uint8_t>(res.kind);
    }
    if (out_lms_leaf_q != nullptr) {
        *out_lms_leaf_q = res.lmsLeafQ;
    }
    return static_cast<int>(code);
}

} // extern "C"
