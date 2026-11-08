// Copyright (c) 2026 The Divi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script/PqStakingVaultScript.h"

#include <cstring>
#include <limits>

namespace
{

static const size_t MAX_PQ_BECH32M_STRING_LEN = 128;

static const char BECH32_CHARSET[33] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static const int8_t BECH32_CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
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

static void Sha256OneShot(const uint8_t* data, size_t len, uint8_t out32[32])
{
    uint32_t h[8] = {
        0x6a09e667UL, 0xbb67ae85UL, 0x3c6ef372UL, 0xa54ff53aUL,
        0x510e527fUL, 0x9b05688cUL, 0x1f83d9abUL, 0x5be0cd19UL
    };
    size_t offset = 0;
    while (offset + 64 <= len) {
        Sha256Compress(h, data + offset);
        offset += 64;
    }

    uint8_t buf[64];
    size_t rem = len - offset;
    if (rem > 0) {
        std::memcpy(buf, data + offset, rem);
    }
    buf[rem++] = 0x80U;
    if (rem > 56) {
        while (rem < 64) {
            buf[rem++] = 0;
        }
        Sha256Compress(h, buf);
        rem = 0;
    }
    while (rem < 56) {
        buf[rem++] = 0;
    }
    uint64_t bitLen = static_cast<uint64_t>(len) * 8ULL;
    for (size_t i = 0; i < 8; ++i) {
        buf[56 + i] = static_cast<uint8_t>((bitLen >> (56U - 8U * i)) & 0xffU);
    }
    Sha256Compress(h, buf);
    for (size_t i = 0; i < 8; ++i) {
        WriteBe32(out32 + i * 4, h[i]);
    }
}

static void DoubleSha256(const uint8_t* data, size_t len, uint8_t out32[32])
{
    uint8_t first[32];
    Sha256OneShot(data, len, first);
    Sha256OneShot(first, 32, out32);
}

static uint32_t Bech32Polymod(const std::vector<uint8_t>& values)
{
    static const uint32_t GEN[5] = {
        0x3b6a57b2UL,
        0x26508e6dUL,
        0x1ea119faUL,
        0x3d4233ddUL,
        0x2a1462b3UL
    };
    uint32_t chk = 1UL;
    for (size_t idx = 0; idx < values.size(); ++idx) {
        uint32_t top = chk >> 25;
        chk = ((chk & 0x01ffffffUL) << 5) ^ static_cast<uint32_t>(values[idx]);
        for (unsigned int i = 0; i < 5; ++i) {
            if (((top >> i) & 1U) != 0U) {
                chk ^= GEN[i];
            }
        }
    }
    return chk;
}

static std::vector<uint8_t> HrpExpand(const std::string& hrp)
{
    std::vector<uint8_t> out;
    out.reserve(hrp.size() * 2 + 1);
    for (size_t i = 0; i < hrp.size(); ++i) {
        uint8_t b = static_cast<uint8_t>(hrp[i]);
        out.push_back(static_cast<uint8_t>(b >> 5));
    }
    out.push_back(0);
    for (size_t i = 0; i < hrp.size(); ++i) {
        uint8_t b = static_cast<uint8_t>(hrp[i]);
        out.push_back(static_cast<uint8_t>(b & 0x1fU));
    }
    return out;
}

static void CreateBech32mChecksum(
    const std::string& hrp,
    const std::vector<uint8_t>& data,
    uint8_t outChecksum[6])
{
    std::vector<uint8_t> values = HrpExpand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    for (size_t i = 0; i < 6; ++i) {
        values.push_back(0);
    }
    uint32_t polymod = Bech32Polymod(values) ^ BECH32M_CONST;
    for (unsigned int i = 0; i < 6; ++i) {
        outChecksum[i] = static_cast<uint8_t>((polymod >> (5U * (5U - i))) & 0x1fU);
    }
}

static PqAddressErrorCode VerifyBech32mChecksum(
    const std::string& hrp,
    const std::vector<uint8_t>& dataWithChecksum)
{
    std::vector<uint8_t> values = HrpExpand(hrp);
    values.insert(values.end(), dataWithChecksum.begin(), dataWithChecksum.end());
    uint32_t residue = Bech32Polymod(values);
    if (residue == BECH32M_CONST) {
        return PqAddressErrorCode::Ok;
    }
    if (residue == BECH32_LEGACY_CONST) {
        return PqAddressErrorCode::LegacyBech32Forbidden;
    }
    return PqAddressErrorCode::ChecksumMismatch;
}

static PqAddressErrorCode ConvertBits(
    const uint8_t* data,
    size_t len,
    unsigned int fromBits,
    unsigned int toBits,
    bool pad,
    std::vector<uint8_t>& out)
{
    uint32_t acc = 0;
    unsigned int bits = 0;
    const uint32_t maxv = (1UL << toBits) - 1UL;
    const uint32_t maxAcc = (1UL << (fromBits + toBits - 1U)) - 1UL;
    out.clear();
    out.reserve((len * fromBits + toBits - 1U) / toBits);

    for (size_t i = 0; i < len; ++i) {
        uint32_t v = static_cast<uint32_t>(data[i]);
        if ((v >> fromBits) != 0U) {
            return PqAddressErrorCode::InvalidPadding;
        }
        acc = ((acc << fromBits) | v) & maxAcc;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            out.push_back(static_cast<uint8_t>((acc >> bits) & maxv));
        }
    }

    if (pad) {
        if (bits > 0) {
            out.push_back(static_cast<uint8_t>((acc << (toBits - bits)) & maxv));
        }
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0U) {
        return PqAddressErrorCode::InvalidPadding;
    }

    return PqAddressErrorCode::Ok;
}

static PqAddressErrorCode ValidateWitnessProgramLen(uint8_t version, size_t len)
{
    size_t expected = 0;
    if (version == PQ_WITNESS_VERSION_P2PQPKH) {
        expected = 32;
    } else if (version == PQ_WITNESS_VERSION_VAULT) {
        expected = 64;
    } else {
        return PqAddressErrorCode::UnsupportedWitnessVersion;
    }
    if (len != expected) {
        return PqAddressErrorCode::InvalidProgramLength;
    }
    return PqAddressErrorCode::Ok;
}

static size_t CompactSizeLen(size_t n)
{
    if (n < 0xfdU) {
        return 1;
    } else if (n <= 0xffffU) {
        return 3;
    } else if (static_cast<uint64_t>(n) <= 0xffffffffULL) {
        return 5;
    } else {
        return 9;
    }
}

static void WriteCompactSize(std::vector<uint8_t>& buf, size_t n)
{
    if (n < 0xfdU) {
        buf.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xffffU) {
        buf.push_back(0xfdU);
        buf.push_back(static_cast<uint8_t>(n & 0xffU));
        buf.push_back(static_cast<uint8_t>((n >> 8) & 0xffU));
    } else if (static_cast<uint64_t>(n) <= 0xffffffffULL) {
        buf.push_back(0xfeU);
        for (unsigned int i = 0; i < 4; ++i) {
            buf.push_back(static_cast<uint8_t>((n >> (8U * i)) & 0xffU));
        }
    } else {
        uint64_t v = static_cast<uint64_t>(n);
        buf.push_back(0xffU);
        for (unsigned int i = 0; i < 8; ++i) {
            buf.push_back(static_cast<uint8_t>((v >> (8U * i)) & 0xffU));
        }
    }
}

static PqWitnessErrorCode ReadCompactSize(
    const uint8_t* bytes,
    size_t len,
    size_t& pos,
    size_t& outVal)
{
    if (pos >= len) {
        return PqWitnessErrorCode::UnexpectedEof;
    }
    uint8_t first = bytes[pos++];
    if (first < 0xfdU) {
        outVal = static_cast<size_t>(first);
        return PqWitnessErrorCode::Ok;
    }
    if (first == 0xfdU) {
        if (pos + 2 > len) {
            return PqWitnessErrorCode::UnexpectedEof;
        }
        uint16_t v = static_cast<uint16_t>(bytes[pos]) |
                     (static_cast<uint16_t>(bytes[pos + 1]) << 8);
        pos += 2;
        if (v < 0xfdU) {
            return PqWitnessErrorCode::NonCanonicalCompactSize;
        }
        outVal = static_cast<size_t>(v);
        return PqWitnessErrorCode::Ok;
    }
    if (first == 0xfeU) {
        if (pos + 4 > len) {
            return PqWitnessErrorCode::UnexpectedEof;
        }
        uint32_t v = static_cast<uint32_t>(bytes[pos]) |
                     (static_cast<uint32_t>(bytes[pos + 1]) << 8) |
                     (static_cast<uint32_t>(bytes[pos + 2]) << 16) |
                     (static_cast<uint32_t>(bytes[pos + 3]) << 24);
        pos += 4;
        if (v <= 0xffffU) {
            return PqWitnessErrorCode::NonCanonicalCompactSize;
        }
        outVal = static_cast<size_t>(v);
        return PqWitnessErrorCode::Ok;
    }
    if (pos + 8 > len) {
        return PqWitnessErrorCode::UnexpectedEof;
    }
    uint64_t v = 0;
    for (unsigned int i = 0; i < 8; ++i) {
        v |= static_cast<uint64_t>(bytes[pos + i]) << (8U * i);
    }
    pos += 8;
    if (v <= 0xffffffffULL || v > static_cast<uint64_t>(std::numeric_limits<size_t>::max())) {
        return PqWitnessErrorCode::NonCanonicalCompactSize;
    }
    outVal = static_cast<size_t>(v);
    return PqWitnessErrorCode::Ok;
}

static bool IsClassicalStakingVaultScriptBytes(
    const std::vector<uint8_t>& script,
    uint8_t outOwnerHash160[20],
    uint8_t outVaultHash160[20])
{
    if (script.size() != CLASSICAL_STAKING_VAULT_SCRIPT_LEN) {
        return false;
    }
    if (script[0] != 0x63U ||
        script[1] != 0x14U ||
        script[22] != 0x67U ||
        script[23] != 0xb9U ||
        script[24] != 0x14U ||
        script[45] != 0x68U ||
        script[46] != 0x78U ||
        script[47] != 0xa9U ||
        script[48] != 0x88U ||
        script[49] != 0xacU) {
        return false;
    }
    if (outOwnerHash160 != nullptr) {
        std::memcpy(outOwnerHash160, script.data() + 2, 20);
    }
    if (outVaultHash160 != nullptr) {
        std::memcpy(outVaultHash160, script.data() + 25, 20);
    }
    return true;
}

} // namespace

const char* PqAddressHrpToString(PqAddressHrp hrp)
{
    switch (hrp) {
    case PqAddressHrp::DiviMainnet:
        return "divi";
    case PqAddressHrp::DiviTestnet:
        return "tdivi";
    case PqAddressHrp::DiviRegtest:
        return "rdivi";
    case PqAddressHrp::PrivateDiviMainnet:
        return "pdivi";
    case PqAddressHrp::PrivateDiviTestnet:
        return "tpdivi";
    }
    return "divi";
}

PqAddressErrorCode ParsePqAddressHrp(const std::string& hrpStr, PqAddressHrp& outHrp)
{
    if (hrpStr == "divi") {
        outHrp = PqAddressHrp::DiviMainnet;
        return PqAddressErrorCode::Ok;
    }
    if (hrpStr == "tdivi") {
        outHrp = PqAddressHrp::DiviTestnet;
        return PqAddressErrorCode::Ok;
    }
    if (hrpStr == "rdivi") {
        outHrp = PqAddressHrp::DiviRegtest;
        return PqAddressErrorCode::Ok;
    }
    if (hrpStr == "pdivi") {
        outHrp = PqAddressHrp::PrivateDiviMainnet;
        return PqAddressErrorCode::Ok;
    }
    if (hrpStr == "tpdivi") {
        outHrp = PqAddressHrp::PrivateDiviTestnet;
        return PqAddressErrorCode::Ok;
    }
    return PqAddressErrorCode::UnknownHrp;
}

std::vector<uint8_t> CreateP2pqpkhScript(const uint8_t addrKeyHash256[32])
{
    std::vector<uint8_t> script(P2PQPKH_SCRIPT_LEN);
    script[0] = 0x51U; // OP_1
    script[1] = 0x20U; // PUSH32
    std::memcpy(&script[2], addrKeyHash256, 32);
    return script;
}

std::vector<uint8_t> CreateP2pqpkhScript(const std::vector<uint8_t>& addrKeyHash256)
{
    if (addrKeyHash256.size() != 32) {
        return std::vector<uint8_t>();
    }
    return CreateP2pqpkhScript(addrKeyHash256.data());
}

bool IsP2pqpkhScript(const std::vector<uint8_t>& script, uint8_t outAddrKeyHash256[32])
{
    if (script.size() != P2PQPKH_SCRIPT_LEN) {
        return false;
    }
    if (script[0] != 0x51U || script[1] != 0x20U) {
        return false;
    }
    if (outAddrKeyHash256 != nullptr) {
        std::memcpy(outAddrKeyHash256, script.data() + 2, 32);
    }
    return true;
}

std::vector<uint8_t> CreatePqStakingVaultScript(
    const uint8_t ownerHash256[32],
    const uint8_t vaultHash256[32])
{
    std::vector<uint8_t> script(PQ_STAKING_VAULT_SCRIPT_LEN);
    script[0] = 0x63U; // OP_IF
    script[1] = 0x20U; // PUSH32
    std::memcpy(&script[2], ownerHash256, 32);
    script[34] = 0x67U; // OP_ELSE
    script[35] = 0xb9U; // OP_REQUIRE_COINSTAKE
    script[36] = 0x20U; // PUSH32
    std::memcpy(&script[37], vaultHash256, 32);
    script[69] = 0x68U; // OP_ENDIF
    script[70] = 0x78U; // OP_OVER
    script[71] = 0xa8U; // OP_SHA256
    script[72] = 0x88U; // OP_EQUALVERIFY
    script[73] = 0xacU; // OP_CHECKSIG
    return script;
}

std::vector<uint8_t> CreatePqStakingVaultScript(
    const std::vector<uint8_t>& ownerHash256,
    const std::vector<uint8_t>& vaultHash256)
{
    if (ownerHash256.size() != 32 || vaultHash256.size() != 32) {
        return std::vector<uint8_t>();
    }
    return CreatePqStakingVaultScript(ownerHash256.data(), vaultHash256.data());
}

bool IsPqStakingVaultScript(
    const std::vector<uint8_t>& script,
    uint8_t outOwnerHash256[32],
    uint8_t outVaultHash256[32])
{
    if (script.size() != PQ_STAKING_VAULT_SCRIPT_LEN) {
        return false;
    }
    if (script[0] != 0x63U ||
        script[1] != 0x20U ||
        script[34] != 0x67U ||
        script[35] != 0xb9U ||
        script[36] != 0x20U ||
        script[69] != 0x68U ||
        script[70] != 0x78U ||
        script[71] != 0xa8U ||
        script[72] != 0x88U ||
        script[73] != 0xacU) {
        return false;
    }
    if (outOwnerHash256 != nullptr) {
        std::memcpy(outOwnerHash256, script.data() + 2, 32);
    }
    if (outVaultHash256 != nullptr) {
        std::memcpy(outVaultHash256, script.data() + 37, 32);
    }
    return true;
}

bool GetPqStakingVaultKeyHashes(
    const std::vector<uint8_t>& script,
    std::pair<std::vector<uint8_t>, std::vector<uint8_t> >& outKeyHashes)
{
    uint8_t owner[32];
    uint8_t vault[32];
    if (!IsPqStakingVaultScript(script, owner, vault)) {
        return false;
    }
    outKeyHashes.first.assign(owner, owner + 32);
    outKeyHashes.second.assign(vault, vault + 32);
    return true;
}

StakingQuantumPosture ClassifyStakingQuantumPosture(const std::vector<uint8_t>& script)
{
    StakingQuantumPosture posture;
    std::memset(posture.ownerHash160, 0, 20);
    std::memset(posture.managerHash160, 0, 20);

    if (IsClassicalStakingVaultScriptBytes(script, posture.ownerHash160, posture.managerHash160)) {
        posture.kind = StakingQuantumPostureKind::VaultInsulated;
        return posture;
    }

    uint8_t owner32[32];
    uint8_t vault32[32];
    if (IsPqStakingVaultScript(script, owner32, vault32)) {
        posture.kind = StakingQuantumPostureKind::VaultInsulated;
        std::memcpy(posture.ownerHash160, owner32, 20);
        std::memcpy(posture.managerHash160, vault32, 20);
        return posture;
    }

    uint8_t addr32[32];
    if (IsP2pqpkhScript(script, addr32)) {
        posture.kind = StakingQuantumPostureKind::VaultInsulated;
        std::memcpy(posture.ownerHash160, addr32, 20);
        std::memcpy(posture.managerHash160, addr32, 20);
        return posture;
    }

    posture.kind = StakingQuantumPostureKind::DirectPubKeyExposed;
    return posture;
}

PqAddressErrorCode EncodePqBech32mAddress(
    PqAddressHrp hrp,
    uint8_t witnessVersion,
    const uint8_t* program,
    size_t programLen,
    std::string& outAddress)
{
    outAddress.clear();
    PqAddressErrorCode lenErr = ValidateWitnessProgramLen(witnessVersion, programLen);
    if (lenErr != PqAddressErrorCode::Ok) {
        return lenErr;
    }
    if (program == nullptr) {
        return PqAddressErrorCode::InvalidProgramLength;
    }

    std::vector<uint8_t> converted;
    PqAddressErrorCode convErr = ConvertBits(program, programLen, 8, 5, true, converted);
    if (convErr != PqAddressErrorCode::Ok) {
        return convErr;
    }

    std::vector<uint8_t> fiveBitData;
    fiveBitData.reserve(1 + converted.size());
    fiveBitData.push_back(witnessVersion);
    fiveBitData.insert(fiveBitData.end(), converted.begin(), converted.end());

    const std::string hrpStr = PqAddressHrpToString(hrp);
    uint8_t checksum[6];
    CreateBech32mChecksum(hrpStr, fiveBitData, checksum);

    outAddress.reserve(hrpStr.size() + 1 + fiveBitData.size() + 6);
    outAddress.append(hrpStr);
    outAddress.push_back('1');
    for (size_t i = 0; i < fiveBitData.size(); ++i) {
        outAddress.push_back(BECH32_CHARSET[fiveBitData[i] & 0x1fU]);
    }
    for (size_t i = 0; i < 6; ++i) {
        outAddress.push_back(BECH32_CHARSET[checksum[i] & 0x1fU]);
    }
    return PqAddressErrorCode::Ok;
}

PqAddressErrorCode DecodePqBech32mAddress(
    const std::string& address,
    PqAddressHrp& outHrp,
    uint8_t& outWitnessVersion,
    std::vector<uint8_t>& outProgram)
{
    outProgram.clear();
    const size_t len = address.size();
    if (len < 8 || len > MAX_PQ_BECH32M_STRING_LEN) {
        return PqAddressErrorCode::InvalidStringLength;
    }

    bool hasLower = false;
    bool hasUpper = false;
    std::string lower;
    lower.resize(len);
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = static_cast<uint8_t>(address[i]);
        if (b < 33U || b > 126U) {
            return PqAddressErrorCode::InvalidCharacter;
        }
        if (b >= 'a' && b <= 'z') {
            hasLower = true;
            lower[i] = static_cast<char>(b);
        } else if (b >= 'A' && b <= 'Z') {
            hasUpper = true;
            lower[i] = static_cast<char>(b - 'A' + 'a');
        } else {
            lower[i] = static_cast<char>(b);
        }
    }
    if (hasLower && hasUpper) {
        return PqAddressErrorCode::MixedCase;
    }

    size_t sepPos = lower.rfind('1');
    if (sepPos == std::string::npos || sepPos == 0 || sepPos + 7 > lower.size()) {
        return PqAddressErrorCode::MissingSeparator;
    }

    const std::string hrpStr = lower.substr(0, sepPos);
    PqAddressErrorCode hrpErr = ParsePqAddressHrp(hrpStr, outHrp);
    if (hrpErr != PqAddressErrorCode::Ok) {
        return hrpErr;
    }

    const size_t dataLen = lower.size() - (sepPos + 1);
    std::vector<uint8_t> dataU5;
    dataU5.reserve(dataLen);
    for (size_t i = 0; i < dataLen; ++i) {
        uint8_t ch = static_cast<uint8_t>(lower[sepPos + 1 + i]);
        if (ch >= 128U) {
            return PqAddressErrorCode::InvalidCharacter;
        }
        int8_t val = BECH32_CHARSET_REV[ch];
        if (val < 0) {
            return PqAddressErrorCode::InvalidCharacter;
        }
        dataU5.push_back(static_cast<uint8_t>(val));
    }

    PqAddressErrorCode chkErr = VerifyBech32mChecksum(hrpStr, dataU5);
    if (chkErr != PqAddressErrorCode::Ok) {
        return chkErr;
    }

    const size_t payloadU5Len = dataU5.size() - 6;
    outWitnessVersion = dataU5[0];
    PqAddressErrorCode convErr = ConvertBits(
        dataU5.data() + 1,
        payloadU5Len - 1,
        5,
        8,
        false,
        outProgram);
    if (convErr != PqAddressErrorCode::Ok) {
        return convErr;
    }

    return ValidateWitnessProgramLen(outWitnessVersion, outProgram.size());
}

PqAddressErrorCode EncodeP2pqpkhAddress(
    PqAddressHrp hrp,
    const uint8_t addrKeyHash256[32],
    std::string& outAddress)
{
    return EncodePqBech32mAddress(hrp, PQ_WITNESS_VERSION_P2PQPKH, addrKeyHash256, 32, outAddress);
}

PqAddressErrorCode EncodePqVaultAddress(
    PqAddressHrp hrp,
    const uint8_t ownerHash256[32],
    const uint8_t vaultHash256[32],
    std::string& outAddress)
{
    uint8_t program[64];
    std::memcpy(program, ownerHash256, 32);
    std::memcpy(program + 32, vaultHash256, 32);
    return EncodePqBech32mAddress(hrp, PQ_WITNESS_VERSION_VAULT, program, 64, outAddress);
}

PqAddressErrorCode PqAddressToScriptPubKey(
    const std::string& address,
    PqAddressHrp& outHrp,
    std::vector<uint8_t>& outScriptPubKey)
{
    uint8_t version = 0;
    std::vector<uint8_t> program;
    PqAddressErrorCode err = DecodePqBech32mAddress(address, outHrp, version, program);
    if (err != PqAddressErrorCode::Ok) {
        return err;
    }
    if (version == PQ_WITNESS_VERSION_P2PQPKH) {
        outScriptPubKey = CreateP2pqpkhScript(program.data());
        return PqAddressErrorCode::Ok;
    }
    if (version == PQ_WITNESS_VERSION_VAULT) {
        outScriptPubKey = CreatePqStakingVaultScript(program.data(), program.data() + 32);
        return PqAddressErrorCode::Ok;
    }
    return PqAddressErrorCode::UnsupportedWitnessVersion;
}

bool ScriptPubKeyToPqAddress(
    PqAddressHrp hrp,
    const std::vector<uint8_t>& scriptPubKey,
    std::string& outAddress)
{
    uint8_t addrHash[32];
    if (IsP2pqpkhScript(scriptPubKey, addrHash)) {
        return EncodeP2pqpkhAddress(hrp, addrHash, outAddress) == PqAddressErrorCode::Ok;
    }
    uint8_t ownerHash[32];
    uint8_t vaultHash[32];
    if (IsPqStakingVaultScript(scriptPubKey, ownerHash, vaultHash)) {
        return EncodePqVaultAddress(hrp, ownerHash, vaultHash, outAddress) == PqAddressErrorCode::Ok;
    }
    return false;
}

PqInputWitness PqInputWitness::Empty()
{
    return PqInputWitness();
}

PqInputWitness PqInputWitness::ForP2pqpkh(
    uint8_t schemeId,
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    uint8_t sighashType)
{
    std::vector<uint8_t> sigItem;
    sigItem.reserve(1 + signature.size() + 1);
    sigItem.push_back(schemeId);
    sigItem.insert(sigItem.end(), signature.begin(), signature.end());
    sigItem.push_back(sighashType);

    std::vector<uint8_t> pkItem;
    pkItem.reserve(1 + pubkey.size());
    pkItem.push_back(schemeId);
    pkItem.insert(pkItem.end(), pubkey.begin(), pubkey.end());

    PqInputWitness w;
    w.items.push_back(sigItem);
    w.items.push_back(pkItem);
    return w;
}

PqInputWitness PqInputWitness::ForPqVault(
    bool isOwnerSpend,
    uint8_t schemeId,
    const std::vector<uint8_t>& pubkey,
    const std::vector<uint8_t>& signature,
    uint8_t sighashType)
{
    PqInputWitness w = ForP2pqpkh(schemeId, pubkey, signature, sighashType);
    if (isOwnerSpend) {
        std::vector<uint8_t> branch(1, 0x01U);
        w.items.push_back(branch);
    } else {
        w.items.push_back(std::vector<uint8_t>());
    }
    return w;
}

size_t PqInputWitness::TotalItemBytes() const
{
    size_t sum = 0;
    for (size_t i = 0; i < items.size(); ++i) {
        sum += items[i].size();
    }
    return sum;
}

size_t PqInputWitness::SerializedSize() const
{
    size_t total = CompactSizeLen(items.size());
    for (size_t i = 0; i < items.size(); ++i) {
        total += CompactSizeLen(items[i].size()) + items[i].size();
    }
    return total;
}

std::vector<uint8_t> PqInputWitness::SerializeCanonical() const
{
    std::vector<uint8_t> buf;
    buf.reserve(SerializedSize());
    WriteCompactSize(buf, items.size());
    for (size_t i = 0; i < items.size(); ++i) {
        WriteCompactSize(buf, items[i].size());
        buf.insert(buf.end(), items[i].begin(), items[i].end());
    }
    return buf;
}

PqWitnessErrorCode PqInputWitness::DeserializeCanonical(
    const uint8_t* data,
    size_t len,
    PqInputWitness& outWitness)
{
    outWitness.items.clear();
    if (len > MAX_PQ_TX_WITNESS_BYTES) {
        return PqWitnessErrorCode::InputWitnessTooLarge;
    }
    if (data == nullptr && len > 0) {
        return PqWitnessErrorCode::UnexpectedEof;
    }

    size_t pos = 0;
    size_t count = 0;
    PqWitnessErrorCode err = ReadCompactSize(data, len, pos, count);
    if (err != PqWitnessErrorCode::Ok) {
        return err;
    }
    if (count > MAX_PQ_WITNESS_STACK_ITEMS) {
        return PqWitnessErrorCode::TooManyStackItems;
    }

    outWitness.items.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        size_t itemLen = 0;
        err = ReadCompactSize(data, len, pos, itemLen);
        if (err != PqWitnessErrorCode::Ok) {
            return err;
        }
        if (itemLen > MAX_PQ_WITNESS_ITEM_SIZE) {
            return PqWitnessErrorCode::ItemTooLarge;
        }
        if (pos + itemLen > len) {
            return PqWitnessErrorCode::UnexpectedEof;
        }
        outWitness.items.push_back(std::vector<uint8_t>(data + pos, data + pos + itemLen));
        pos += itemLen;
    }

    if (pos != len) {
        return PqWitnessErrorCode::TrailingBytes;
    }
    return ValidatePqWitnessLimits(outWitness);
}

void PqInputWitness::LeafHash(uint8_t outLeafHash32[32]) const
{
    std::vector<uint8_t> ser = SerializeCanonical();
    DoubleSha256(ser.data(), ser.size(), outLeafHash32);
}

PqWitnessErrorCode ValidatePqWitnessLimits(const PqInputWitness& witness)
{
    if (witness.items.size() > MAX_PQ_WITNESS_STACK_ITEMS) {
        return PqWitnessErrorCode::TooManyStackItems;
    }
    for (size_t i = 0; i < witness.items.size(); ++i) {
        if (witness.items[i].size() > MAX_PQ_WITNESS_ITEM_SIZE) {
            return PqWitnessErrorCode::ItemTooLarge;
        }
    }
    if (witness.SerializedSize() > MAX_PQ_TX_WITNESS_BYTES) {
        return PqWitnessErrorCode::InputWitnessTooLarge;
    }
    return PqWitnessErrorCode::Ok;
}

static void ComputeBinaryMerkleRoot32(
    const std::vector<std::vector<uint8_t> >& leaves,
    uint8_t outRoot32[32])
{
    if (leaves.empty()) {
        std::memset(outRoot32, 0, 32);
        return;
    }
    std::vector<std::vector<uint8_t> > layer = leaves;
    while (layer.size() > 1) {
        if ((layer.size() & 1U) != 0U) {
            layer.push_back(layer.back());
        }
        std::vector<std::vector<uint8_t> > next;
        next.reserve(layer.size() / 2);
        for (size_t i = 0; i < layer.size(); i += 2) {
            uint8_t combined[64];
            std::memcpy(combined, layer[i].data(), 32);
            std::memcpy(combined + 32, layer[i + 1].data(), 32);
            std::vector<uint8_t> parent(32);
            DoubleSha256(combined, 64, parent.data());
            next.push_back(parent);
        }
        layer.swap(next);
    }
    std::memcpy(outRoot32, layer[0].data(), 32);
}

void ComputePqWitnessMerkleRoot(
    const std::vector<PqInputWitness>& witnesses,
    uint8_t outMerkleRoot32[32])
{
    bool allEmpty = true;
    for (size_t i = 0; i < witnesses.size(); ++i) {
        if (!witnesses[i].IsEmpty()) {
            allEmpty = false;
            break;
        }
    }
    if (witnesses.empty() || allEmpty) {
        std::memset(outMerkleRoot32, 0, 32);
        return;
    }

    std::vector<std::vector<uint8_t> > leaves;
    leaves.reserve(witnesses.size());
    for (size_t i = 0; i < witnesses.size(); ++i) {
        std::vector<uint8_t> leaf(32);
        witnesses[i].LeafHash(leaf.data());
        leaves.push_back(leaf);
    }
    ComputeBinaryMerkleRoot32(leaves, outMerkleRoot32);
}

void ComputePqWitnessId(
    const uint8_t txid32[32],
    const std::vector<PqInputWitness>& witnesses,
    uint8_t outWtxid32[32])
{
    bool allEmpty = true;
    for (size_t i = 0; i < witnesses.size(); ++i) {
        if (!witnesses[i].IsEmpty()) {
            allEmpty = false;
            break;
        }
    }
    if (witnesses.empty() || allEmpty) {
        std::memcpy(outWtxid32, txid32, 32);
        return;
    }

    uint8_t witnessRoot[32];
    ComputePqWitnessMerkleRoot(witnesses, witnessRoot);
    uint8_t preimage[64];
    std::memcpy(preimage, txid32, 32);
    std::memcpy(preimage + 32, witnessRoot, 32);
    DoubleSha256(preimage, 64, outWtxid32);
}

void ComputeBlockWitnessMerkleRoot(
    const std::vector<std::vector<uint8_t> >& txWtxids,
    uint8_t outBlockWitnessRoot32[32])
{
    if (txWtxids.empty()) {
        std::memset(outBlockWitnessRoot32, 0, 32);
        return;
    }
    std::vector<std::vector<uint8_t> > leaves;
    leaves.reserve(txWtxids.size());
    for (size_t i = 0; i < txWtxids.size(); ++i) {
        if (txWtxids[i].size() == 32) {
            leaves.push_back(txWtxids[i]);
        } else {
            leaves.push_back(std::vector<uint8_t>(32, 0));
        }
    }
    ComputeBinaryMerkleRoot32(leaves, outBlockWitnessRoot32);
}

bool VerifyCoinstakeWitnessCommitment(
    const uint8_t headerOrCommittedRoot32[32],
    const uint8_t computedWitnessRoot32[32])
{
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; ++i) {
        diff |= static_cast<uint8_t>(headerOrCommittedRoot32[i] ^ computedWitnessRoot32[i]);
    }
    return diff == 0;
}

size_t ComputeBlockWeight(size_t baseBytes, size_t witnessBytes)
{
    const size_t maxSize = std::numeric_limits<size_t>::max();
    size_t scaledBase = (baseBytes > maxSize / PQ_WITNESS_SCALE_FACTOR)
        ? maxSize
        : (baseBytes * PQ_WITNESS_SCALE_FACTOR);
    if (witnessBytes > maxSize - scaledBase) {
        return maxSize;
    }
    return scaledBase + witnessBytes;
}

PqWitnessErrorCode ValidatePqBlockWeight(
    size_t baseBytes,
    size_t witnessBytes,
    size_t& outWeight)
{
    outWeight = ComputeBlockWeight(baseBytes, witnessBytes);
    const size_t maxSize = std::numeric_limits<size_t>::max();
    size_t rawBytes = (witnessBytes > maxSize - baseBytes) ? maxSize : (baseBytes + witnessBytes);
    if (outWeight > MAX_PQ_BLOCK_WEIGHT || rawBytes > MAX_PQ_BLOCK_RAW_BYTES) {
        return PqWitnessErrorCode::BlockWeightExceeded;
    }
    return PqWitnessErrorCode::Ok;
}

extern "C" {

int divi_cpp_encode_pq_bech32m_address(
    uint8_t hrp_code,
    uint8_t witness_version,
    const uint8_t* program_ptr,
    size_t program_len,
    char* out_str_buf,
    size_t out_str_capacity,
    size_t* out_str_len)
{
    if (hrp_code > 4) {
        return static_cast<int>(PqAddressErrorCode::UnknownHrp);
    }
    std::string encoded;
    PqAddressErrorCode err = EncodePqBech32mAddress(
        static_cast<PqAddressHrp>(hrp_code),
        witness_version,
        program_ptr,
        program_len,
        encoded);
    if (err != PqAddressErrorCode::Ok) {
        return static_cast<int>(err);
    }
    if (out_str_len != nullptr) {
        *out_str_len = encoded.size();
    }
    if (out_str_buf != nullptr) {
        if (out_str_capacity < encoded.size()) {
            return -1;
        }
        std::memcpy(out_str_buf, encoded.data(), encoded.size());
    }
    return 0;
}

int divi_cpp_decode_pq_bech32m_address(
    const char* addr_ptr,
    size_t addr_len,
    uint8_t* out_hrp_code,
    uint8_t* out_witness_version,
    uint8_t* out_program_buf,
    size_t out_program_capacity,
    size_t* out_program_len)
{
    std::string addr(addr_ptr != nullptr ? addr_ptr : "", addr_ptr != nullptr ? addr_len : 0);
    PqAddressHrp hrp = PqAddressHrp::DiviMainnet;
    uint8_t ver = 0;
    std::vector<uint8_t> prog;
    PqAddressErrorCode err = DecodePqBech32mAddress(addr, hrp, ver, prog);
    if (err != PqAddressErrorCode::Ok) {
        return static_cast<int>(err);
    }
    if (out_hrp_code != nullptr) {
        *out_hrp_code = static_cast<uint8_t>(hrp);
    }
    if (out_witness_version != nullptr) {
        *out_witness_version = ver;
    }
    if (out_program_len != nullptr) {
        *out_program_len = prog.size();
    }
    if (out_program_buf != nullptr) {
        if (out_program_capacity < prog.size()) {
            return -1;
        }
        std::memcpy(out_program_buf, prog.data(), prog.size());
    }
    return 0;
}

void divi_cpp_create_p2pqpkh_script(
    const uint8_t addr_key_hash_256[32],
    uint8_t out_script34[34])
{
    std::vector<uint8_t> s = CreateP2pqpkhScript(addr_key_hash_256);
    std::memcpy(out_script34, s.data(), P2PQPKH_SCRIPT_LEN);
}

void divi_cpp_create_pq_staking_vault_script(
    const uint8_t owner_hash_256[32],
    const uint8_t vault_hash_256[32],
    uint8_t out_script74[74])
{
    std::vector<uint8_t> s = CreatePqStakingVaultScript(owner_hash_256, vault_hash_256);
    std::memcpy(out_script74, s.data(), PQ_STAKING_VAULT_SCRIPT_LEN);
}

int divi_cpp_extract_pq_staking_vault_hashes(
    const uint8_t* script_ptr,
    size_t script_len,
    uint8_t out_owner_hash_256[32],
    uint8_t out_vault_hash_256[32])
{
    std::vector<uint8_t> s;
    if (script_ptr != nullptr && script_len > 0) {
        s.assign(script_ptr, script_ptr + script_len);
    }
    return IsPqStakingVaultScript(s, out_owner_hash_256, out_vault_hash_256) ? 0 : -1;
}

void divi_cpp_compute_wtxid_from_serialized_witnesses(
    const uint8_t txid32[32],
    const uint8_t* serialized_witnesses_concat,
    const size_t* witness_lengths,
    size_t witness_count,
    uint8_t out_wtxid32[32],
    uint8_t out_witness_merkle_root32[32])
{
    std::vector<PqInputWitness> witnesses;
    witnesses.reserve(witness_count);
    size_t offset = 0;
    for (size_t i = 0; i < witness_count; ++i) {
        size_t wLen = witness_lengths[i];
        PqInputWitness w;
        if (PqInputWitness::DeserializeCanonical(
                serialized_witnesses_concat + offset,
                wLen,
                w) == PqWitnessErrorCode::Ok) {
            witnesses.push_back(w);
        }
        offset += wLen;
    }
    ComputePqWitnessMerkleRoot(witnesses, out_witness_merkle_root32);
    ComputePqWitnessId(txid32, witnesses, out_wtxid32);
}

int divi_cpp_validate_pq_block_weight(
    size_t base_bytes,
    size_t witness_bytes,
    size_t* out_weight)
{
    size_t w = 0;
    PqWitnessErrorCode err = ValidatePqBlockWeight(base_bytes, witness_bytes, w);
    if (out_weight != nullptr) {
        *out_weight = w;
    }
    return static_cast<int>(err);
}

} // extern "C"
