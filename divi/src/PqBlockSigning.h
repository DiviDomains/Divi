// Copyright (c) 2026 The Divi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DIVI_PQ_BLOCK_SIGNING_H
#define DIVI_PQ_BLOCK_SIGNING_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "pqcrypto/divi_pqcrypto.h"

/**
 * DIP-PQ-4: Post-Quantum Proof-of-Stake Block Signing (`vchBlockSig` Envelope,
 * Coinstake Vault Binding & Cutoff Policy).
 *
 * Implements lockstep C++11 parity with IronDivi `crates/divi-consensus/src/pq_block_sig.rs`
 * and `docs/plans/dip-pq-4-pos-block-signing.md`.
 */
namespace PqBlockSigning
{

static const uint8_t PQ_BLOCK_SIG_MAGIC = 0x50U;
static const uint8_t PQ_BLOCK_SIG_VERSION_V1 = 0x01U;
static const size_t PQ_BLOCK_SIG_HEADER_LEN = 3;

static const size_t FN_DSA_512_BLOCK_SIG_ENVELOPE_LEN = PQ_BLOCK_SIG_HEADER_LEN + 897 + 666;   // 1,566 B
static const size_t ML_DSA_44_BLOCK_SIG_ENVELOPE_LEN = PQ_BLOCK_SIG_HEADER_LEN + 1312 + 2420;  // 3,735 B
static const size_t CLASSICAL_COMPACT_BLOCK_SIG_LEN = 65;

static const size_t POS_BLOCK_PAYLOAD_DOMAIN_LEN = 17; // "DIVI-POS-BLOCK-V1"
static const size_t POS_BLOCK_PAYLOAD_PREIMAGE_LEN = 17 + 32 + 32 + 4; // 85 B

enum class PqBlockSigErrorCode : uint8_t {
    Ok = 0,
    EmptyBlockSignature = 1,
    InvalidEnvelopeMagic = 2,
    UnsupportedEnvelopeVersion = 3,
    InvalidEnvelopeLength = 4,
    InvalidClassicalSignatureFormat = 5,
    PostQuantumBlockSigForbiddenBeforeActivation = 6,
    MissingPostQuantumBlockSigForPqOutput = 7,
    MissingPostQuantumBlockSigAfterCutoff = 8,
    UnsupportedCoinstakeScriptForPqBlockSig = 9,
    UnsupportedCoinstakeScriptForClassicalBlockSig = 10,
    ColdOwnerKeyForbiddenForBlockSigning = 11,
    StakerKeyHashMismatch = 12,
    SchemeForbiddenInDomain = 13,
    UnknownSchemeId = 14,
    CryptoValidationError = 15
};

enum class CoinstakeBindingKind : uint8_t {
    PqStakingVault = 0,
    P2PqPkh = 1
};

struct CoinstakeStakerBinding {
    CoinstakeBindingKind kind;
    uint8_t ownerHash256[32];
    uint8_t vaultHash256[32];
    uint8_t addrKeyHash256[32];

    const uint8_t* ExpectedStakerHash256() const
    {
        return (kind == CoinstakeBindingKind::PqStakingVault) ? vaultHash256 : addrKeyHash256;
    }
};

struct PqBlockSigEnvelope {
    uint8_t schemeId;
    std::vector<uint8_t> pubkeyBytes;
    std::vector<uint8_t> signatureBytes;

    PqBlockSigEnvelope();

    static PqBlockSigErrorCode ExpectedEnvelopeLen(uint8_t schemeId, size_t& outLen);

    static PqBlockSigErrorCode Create(
        uint8_t schemeId,
        const std::vector<uint8_t>& pubkeyBytes,
        const std::vector<uint8_t>& signatureBytes,
        PqBlockSigEnvelope& outEnvelope,
        int* outPqError = nullptr);

    std::vector<uint8_t> Encode() const;

    static PqBlockSigErrorCode Decode(
        const uint8_t* bytes,
        size_t len,
        PqBlockSigEnvelope& outEnvelope,
        int* outPqError = nullptr);

    static PqBlockSigErrorCode Decode(
        const std::vector<uint8_t>& bytes,
        PqBlockSigEnvelope& outEnvelope,
        int* outPqError = nullptr);

    void StakerKeyHash256(uint8_t outHash32[32]) const;
    void SigningKeyHash256(uint8_t outHash32[32]) const;

    PqBlockSigErrorCode VerifyStructuralAndStakerBinding(
        const std::vector<uint8_t>& coinstakeScriptPubKey,
        CoinstakeStakerBinding& outBinding,
        int* outPqError = nullptr) const;
};

enum class BlockSigFormatKind : uint8_t {
    ClassicalSecp256k1 = 0,
    PostQuantumV1 = 1
};

struct BlockSigFormat {
    BlockSigFormatKind kind;
    PqBlockSigEnvelope pqEnvelope;
};

enum class PosBlockPolicyStage : uint8_t {
    ClassicalOnly = 0,
    DualAllowed = 1,
    PqRequiredForPqOutputs = 2,
    PqRequiredAllAfter = 3
};

struct PosBlockAuthPolicy {
    PosBlockPolicyStage stage;
    uint8_t networkMagic[4];
    uint32_t cutoffBlockTime;

    PosBlockAuthPolicy();

    static PosBlockAuthPolicy ClassicalOnly();
    static PosBlockAuthPolicy DualAllowed(const uint8_t magic4[4]);
    static PosBlockAuthPolicy PqRequiredForPqOutputs(const uint8_t magic4[4]);
    static PosBlockAuthPolicy PqRequiredAllAfter(const uint8_t magic4[4], uint32_t cutoffTime);
};

struct VerifiedBlockSigBinding {
    BlockSigFormatKind kind;
    uint8_t schemeId;
    uint8_t stakerKeyHash256[32];
    CoinstakeStakerBinding coinstakeBinding;
    uint8_t payloadHash256[32];
    uint8_t signingPrehash512[64];
};

bool ParsePqCoinstakeScript(
    const std::vector<uint8_t>& scriptPubKey,
    CoinstakeStakerBinding& outBinding);

bool IsClassicalCoinstakeScript(const std::vector<uint8_t>& scriptPubKey);

PqBlockSigErrorCode ClassifyBlockSigFormat(
    const std::vector<uint8_t>& vchBlockSig,
    BlockSigFormat& outFormat,
    int* outPqError = nullptr);

void SerializePosBlockPayloadPreimage(
    const uint8_t blockHash32[32],
    const uint8_t coinstakeTxid32[32],
    uint32_t coinstakeVout,
    uint8_t outPreimage85[POS_BLOCK_PAYLOAD_PREIMAGE_LEN]);

void ComputePosBlockPayloadHash(
    const uint8_t blockHash32[32],
    const uint8_t coinstakeTxid32[32],
    uint32_t coinstakeVout,
    uint8_t outPayloadHash32[32]);

PqBlockSigErrorCode ComputePosBlockSigningPrehash(
    const uint8_t networkMagic4[4],
    uint8_t schemeId,
    const uint8_t* pubkeyBytes,
    size_t pubkeyLen,
    const uint8_t blockHash32[32],
    const uint8_t coinstakeTxid32[32],
    uint32_t coinstakeVout,
    uint8_t outPrehash64[64],
    int* outPqError = nullptr);

PqBlockSigErrorCode VerifyBlockSigEnvelopeBinding(
    const std::vector<uint8_t>& vchBlockSig,
    const std::vector<uint8_t>& coinstakeScriptPubKey,
    const uint8_t blockHash32[32],
    const uint8_t coinstakeTxid32[32],
    uint32_t coinstakeVout,
    uint32_t blockTime,
    const PosBlockAuthPolicy& policy,
    VerifiedBlockSigBinding& outVerified,
    int* outPqError = nullptr);

} // namespace PqBlockSigning

extern "C" {

void divi_cpp_pos_block_payload_hash(
    const uint8_t block_hash32[32],
    const uint8_t coinstake_txid32[32],
    uint32_t coinstake_vout,
    uint8_t out_payload_hash32[32]);

int divi_cpp_pos_block_signing_prehash(
    const uint8_t network_magic4[4],
    uint8_t scheme_id,
    const uint8_t* pubkey_ptr,
    size_t pubkey_len,
    const uint8_t block_hash32[32],
    const uint8_t coinstake_txid32[32],
    uint32_t coinstake_vout,
    uint8_t out_prehash64[64]);

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
    uint8_t out_signing_prehash64[64]);

} // extern "C"

#endif // DIVI_PQ_BLOCK_SIGNING_H
