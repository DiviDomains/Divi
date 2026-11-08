// Copyright (c) 2026 The Divi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DIVI_SPORK_PQ_H
#define DIVI_SPORK_PQ_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "pqcrypto/divi_pqcrypto.h"

/**
 * DIP-PQ-2: Hybrid Classical + Post-Quantum Spork Authentication (secp256k1 + LMS-SHA256-M32-H10)
 *
 * Implements lockstep C++11 parity with IronDivi `crates/divi-network/src/spork.rs`
 * and `docs/plans/dip-pq-2-hybrid-sporks.md`:
 *   - 65-byte classical secp256k1 compact signature (`CLASSICAL_SPORK_SIG_LEN = 65`)
 *   - 2,512-byte stateful hash-based `LMS-SHA256-M32-H10` / `LMOTS-SHA256-N32-W4` signature (`PQ_LMS_SPORK_SIG_LEN = 2512`)
 *   - 2,577-byte hybrid `CSporkMessage` v2 signature (`HYBRID_SPORK_SIG_LEN = 2577`)
 *   - Canonical `DIVI-SPORK-PAYLOAD-V1` 32-byte payload hashing (106-byte integer Case A vs >=107-byte string Case B)
 *   - 64-byte `SHA-512` `Divi-PQ-Spork-v1` signing prehash (`scheme_id = 0x04`)
 *   - Three-stage `SporkAuthPolicy` (`ClassicalOnly`, `HybridOptional`, `HybridRequiredAfter`)
 *   - Stateful `LMS` `q_leaf` monotonicity and leaf reuse tracking (`SporkLmsStateTracker`)
 */
namespace SporkPq
{

static const size_t CLASSICAL_SPORK_SIG_LEN = 65;
static const size_t PQ_LMS_SPORK_SIG_LEN = DIVI_PQ_LMS_H10_SIG_LEN;
static const size_t PQ_LMS_SPORK_PUBKEY_LEN = DIVI_PQ_LMS_H10_PUBKEY_LEN;
static const size_t HYBRID_SPORK_SIG_LEN = CLASSICAL_SPORK_SIG_LEN + PQ_LMS_SPORK_SIG_LEN;
static const size_t SPORK_PQ_PAYLOAD_DOMAIN_LEN = 21; // "DIVI-SPORK-PAYLOAD-V1"

enum class SporkPolicyStage : uint8_t {
    ClassicalOnly = 0,
    HybridOptional = 1,
    HybridRequiredAfter = 2
};

struct SporkAuthPolicy {
    SporkPolicyStage stage;
    uint8_t pqSporkPubkey[PQ_LMS_SPORK_PUBKEY_LEN];
    uint8_t networkMagic[4];
    int64_t cutoffTimeSigned;

    SporkAuthPolicy();

    static SporkAuthPolicy ClassicalOnly();
    static SporkAuthPolicy HybridOptional(
        const uint8_t pqPubkey60[PQ_LMS_SPORK_PUBKEY_LEN],
        const uint8_t magic4[4]);
    static SporkAuthPolicy HybridRequiredAfter(
        const uint8_t pqPubkey60[PQ_LMS_SPORK_PUBKEY_LEN],
        const uint8_t magic4[4],
        int64_t cutoffTime);
};

enum class SporkAuthKind : uint8_t {
    ClassicalV1 = 0,
    HybridV2 = 1
};

struct SporkVerifyResult {
    SporkAuthKind kind;
    uint32_t lmsLeafQ;
};

enum class SporkVerifyErrorCode : uint8_t {
    Ok = 0,
    InvalidSignatureLength = 1,
    InvalidClassicalSignature = 2,
    MissingPostQuantumSignatureAfterCutoff = 3,
    InvalidPostQuantumSignature = 4,
    LmsLeafReusedAcrossDistinctMessages = 5,
    LmsLeafNonMonotonic = 6
};

/**
 * Compute the 32-byte DIP-PQ-2 §3.1 payload_hash_256 for an integer-valued Spork (106-byte preimage):
 * SHA256("DIVI-SPORK-PAYLOAD-V1" || i32_le(spork_id) || i64_le(value) || i64_le(time_signed) || sig_secp256k1[65]).
 */
void ComputeSporkPqPayloadHashI64(
    int32_t sporkId,
    int64_t value,
    int64_t timeSigned,
    const uint8_t sigSecp256k1[CLASSICAL_SPORK_SIG_LEN],
    uint8_t outHash32[32]);

/**
 * Compute the 32-byte DIP-PQ-2 §3.1 payload_hash_256 for an arbitrary Spork value string:
 * - Case A (canonical base-10 i64 string): 106-byte integer preimage
 * - Case B (multi-value string e.g. "5000;100"):
 *   SHA256("DIVI-SPORK-PAYLOAD-V1" || i32_le(spork_id) || u64_le(|value|) || 0xff || value || i64_le(time_signed) || sig_secp256k1[65]).
 */
void ComputeSporkPqPayloadHash(
    int32_t sporkId,
    const std::string& value,
    int64_t timeSigned,
    const uint8_t sigSecp256k1[CLASSICAL_SPORK_SIG_LEN],
    uint8_t outHash32[32]);

/**
 * Compute the 64-byte (SHA-512) domain-separated DIP-PQ-1 / DIP-PQ-2 signing prehash under
 * "Divi-PQ-Spork-v1" and scheme 0x04 (LMS-SHA256-M32-H10).
 */
bool ComputeSporkPqSigningPrehash(
    int32_t sporkId,
    const std::string& value,
    int64_t timeSigned,
    const uint8_t sigSecp256k1[CLASSICAL_SPORK_SIG_LEN],
    const uint8_t networkMagic[4],
    const uint8_t pqSporkPubkey[PQ_LMS_SPORK_PUBKEY_LEN],
    uint8_t outPrehash64[64]);

/**
 * Extract the big-endian LMS leaf index q in [0, 1023] from a 2,577-byte hybrid v2 Spork signature.
 */
bool ExtractHybridSporkLmsLeafIndex(
    const std::vector<uint8_t>& vchSig,
    uint32_t& outLmsLeafQ);

/**
 * Verify a Spork v1 (65 B) or hybrid v2 (2,577 B) signature under the active SporkAuthPolicy.
 * `classicalSignatureValid` indicates whether the 65-byte classical secp256k1 prefix passed verification
 * (including recovery header byte in 31..=34).
 */
SporkVerifyErrorCode VerifySporkWithPolicy(
    int32_t sporkId,
    const std::string& value,
    int64_t timeSigned,
    const std::vector<uint8_t>& vchSig,
    bool classicalSignatureValid,
    const SporkAuthPolicy& policy,
    SporkVerifyResult& outResult,
    int* outPqError = nullptr);

/**
 * Direct hybrid v2 (2,577 B) verifier matching `verify_hybrid_spork_v2`.
 */
SporkVerifyErrorCode verify_hybrid_spork_v2(
    int32_t sporkId,
    const std::string& value,
    int64_t timeSigned,
    const uint8_t hybridSig2577[HYBRID_SPORK_SIG_LEN],
    bool classicalSignatureValid,
    const uint8_t networkMagic[4],
    const uint8_t pqSporkPubkey[PQ_LMS_SPORK_PUBKEY_LEN],
    uint32_t& outLmsLeafQ,
    int* outPqError = nullptr);

/**
 * Stateful LMS leaf index (q_leaf) monotonicity and one-time leaf reuse tracker (`DIP-PQ-2` §5.2).
 */
class SporkLmsStateTracker
{
private:
    bool hasLastGlobalQ_;
    uint32_t lastGlobalQ_;
    std::map<int32_t, uint32_t> perSporkLastQ_;
    std::map<uint32_t, std::vector<uint8_t> > observedLeafMessageHash_;

public:
    SporkLmsStateTracker();

    void Reset();

    bool HasLastGlobalLeafIndex() const;
    uint32_t LastGlobalLeafIndex() const;

    bool GetSporkLastLeafIndex(int32_t sporkId, uint32_t& outLeafQ) const;

    /**
     * Record and validate a verified HybridV2 Spork LMS leaf index q.
     * - Rejects one-time leaf reuse across distinct Spork message hashes (`LmsLeafReusedAcrossDistinctMessages`).
     * - If `enforceStrictMonotonicPerSpork` is true, rejects `lmsLeafQ <= prev_q` for the same `sporkId`
     *   when the message hash differs (`LmsLeafNonMonotonic`).
     */
    SporkVerifyErrorCode RecordVerifiedLeaf(
        int32_t sporkId,
        const uint8_t sporkMessageHash32[32],
        uint32_t lmsLeafQ,
        bool enforceStrictMonotonicPerSpork = true);
};

} // namespace SporkPq

extern "C" {

void divi_cpp_spork_pq_payload_hash_i64(
    int32_t spork_id,
    int64_t value,
    int64_t time_signed,
    const uint8_t sig_secp256k1[65],
    uint8_t out_hash32[32]);

void divi_cpp_spork_pq_payload_hash_str(
    int32_t spork_id,
    const uint8_t* value_ptr,
    size_t value_len,
    int64_t time_signed,
    const uint8_t sig_secp256k1[65],
    uint8_t out_hash32[32]);

int divi_cpp_spork_pq_signing_prehash(
    int32_t spork_id,
    const uint8_t* value_ptr,
    size_t value_len,
    int64_t time_signed,
    const uint8_t sig_secp256k1[65],
    const uint8_t network_magic[4],
    const uint8_t pq_spork_pubkey[60],
    uint8_t out_prehash64[64]);

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
    uint32_t* out_lms_leaf_q);

} // extern "C"

#endif // DIVI_SPORK_PQ_H
