// Copyright (c) 2026 The Divi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DIVI_PQ_STAKING_VAULT_SCRIPT_H
#define DIVI_PQ_STAKING_VAULT_SCRIPT_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

/**
 * DIP-PQ-3: Segregated Post-Quantum Witness, BIP-350 Bech32m 256-Bit Addresses &
 * 256-Bit PQ_STAKING_VAULT / P2PQPKH Script Templates.
 *
 * Implements lockstep C++11 parity with IronDivi `crates/divi-script/src/vault.rs`
 * and `docs/plans/dip-pq-3-witness-and-vaults.md`.
 */

static const size_t P2PQPKH_SCRIPT_LEN = 34;
static const size_t PQ_STAKING_VAULT_SCRIPT_LEN = 74;
static const size_t CLASSICAL_STAKING_VAULT_SCRIPT_LEN = 50;

static const uint8_t PQ_WITNESS_VERSION_P2PQPKH = 1;
static const uint8_t PQ_WITNESS_VERSION_VAULT = 2;

static const uint32_t BECH32M_CONST = 0x2bc830a3UL;
static const uint32_t BECH32_LEGACY_CONST = 1UL;

static const size_t MAX_PQ_WITNESS_ITEM_SIZE = 8192;
static const size_t MAX_PQ_TX_WITNESS_BYTES = 16384;
static const size_t MAX_PQ_WITNESS_STACK_ITEMS = 8;

static const size_t PQ_WITNESS_SCALE_FACTOR = 4;
static const size_t MAX_PQ_BLOCK_WEIGHT = 8000000;
static const size_t MAX_PQ_BLOCK_RAW_BYTES = 2000000;

enum class PqAddressHrp : uint8_t {
    DiviMainnet = 0,        // "divi"
    DiviTestnet = 1,        // "tdivi"
    DiviRegtest = 2,        // "rdivi"
    PrivateDiviMainnet = 3, // "pdivi"
    PrivateDiviTestnet = 4  // "tpdivi"
};

enum class PqAddressErrorCode : uint8_t {
    Ok = 0,
    InvalidStringLength = 1,
    MixedCase = 2,
    MissingSeparator = 3,
    UnknownHrp = 4,
    InvalidCharacter = 5,
    ChecksumMismatch = 6,
    LegacyBech32Forbidden = 7,
    UnsupportedWitnessVersion = 8,
    InvalidProgramLength = 9,
    InvalidPadding = 10
};

enum class PqWitnessErrorCode : uint8_t {
    Ok = 0,
    TooManyStackItems = 1,
    ItemTooLarge = 2,
    InputWitnessTooLarge = 3,
    UnexpectedEof = 4,
    NonCanonicalCompactSize = 5,
    TrailingBytes = 6,
    BlockWeightExceeded = 7
};

enum class StakingQuantumPostureKind : uint8_t {
    VaultInsulated = 0,
    DirectPubKeyExposed = 1
};

struct StakingQuantumPosture {
    StakingQuantumPostureKind kind;
    uint8_t ownerHash160[20];
    uint8_t managerHash160[20];

    bool IsVaultInsulated() const { return kind == StakingQuantumPostureKind::VaultInsulated; }
    bool IsDirectPubKeyExposed() const { return kind == StakingQuantumPostureKind::DirectPubKeyExposed; }
    const char* AdvisoryLabel() const
    {
        return IsVaultInsulated() ? "vault_only" : "mixed_or_direct_p2pkh";
    }
};

const char* PqAddressHrpToString(PqAddressHrp hrp);
PqAddressErrorCode ParsePqAddressHrp(const std::string& hrpStr, PqAddressHrp& outHrp);

/**
 * Create a canonical 34-byte P2PQPKH scriptPubKey (`0x51 0x20 <32-byte addr_key_hash_256>`).
 */
std::vector<uint8_t> CreateP2pqpkhScript(const uint8_t addrKeyHash256[32]);
std::vector<uint8_t> CreateP2pqpkhScript(const std::vector<uint8_t>& addrKeyHash256);

/**
 * Check whether `script` is a canonical 34-byte P2PQPKH output script (`OP_1 0x20 <32B>`).
 */
bool IsP2pqpkhScript(const std::vector<uint8_t>& script, uint8_t outAddrKeyHash256[32] = nullptr);

/**
 * Create a canonical 74-byte PQ_STAKING_VAULT scriptPubKey:
 * `OP_IF 0x20 <owner_hash_256> OP_ELSE OP_REQUIRE_COINSTAKE 0x20 <vault_hash_256> OP_ENDIF OP_OVER OP_SHA256 OP_EQUALVERIFY OP_CHECKSIG`
 */
std::vector<uint8_t> CreatePqStakingVaultScript(
    const uint8_t ownerHash256[32],
    const uint8_t vaultHash256[32]);
std::vector<uint8_t> CreatePqStakingVaultScript(
    const std::vector<uint8_t>& ownerHash256,
    const std::vector<uint8_t>& vaultHash256);

/**
 * Check whether `script` is a canonical 74-byte PQ_STAKING_VAULT output script.
 */
bool IsPqStakingVaultScript(
    const std::vector<uint8_t>& script,
    uint8_t outOwnerHash256[32] = nullptr,
    uint8_t outVaultHash256[32] = nullptr);

/**
 * Extract the 32-byte `(owner_hash_256, vault_hash_256)` commitments from a 74-byte PQ_STAKING_VAULT script.
 */
bool GetPqStakingVaultKeyHashes(
    const std::vector<uint8_t>& script,
    std::pair<std::vector<uint8_t>, std::vector<uint8_t> >& outKeyHashes);

/**
 * Classify a scriptPubKey into its post-quantum staking posture (`VaultInsulated` vs `DirectPubKeyExposed`).
 */
StakingQuantumPosture ClassifyStakingQuantumPosture(const std::vector<uint8_t>& script);

/**
 * Encode a DIP-PQ-3 post-quantum witness address using BIP-350 Bech32m (`0x2bc830a3`).
 * - `witnessVersion == 1` (`P2PQPKH`): `programLen == 32`
 * - `witnessVersion == 2` (`PQ_STAKING_VAULT`): `programLen == 64`
 */
PqAddressErrorCode EncodePqBech32mAddress(
    PqAddressHrp hrp,
    uint8_t witnessVersion,
    const uint8_t* program,
    size_t programLen,
    std::string& outAddress);

/**
 * Decode and verify a DIP-PQ-3 BIP-350 Bech32m post-quantum address into `(hrp, witnessVersion, program)`.
 * Explicitly rejects legacy BIP-173 Bech32 checksums (`0x00000001`) with `LegacyBech32Forbidden`.
 */
PqAddressErrorCode DecodePqBech32mAddress(
    const std::string& address,
    PqAddressHrp& outHrp,
    uint8_t& outWitnessVersion,
    std::vector<uint8_t>& outProgram);

PqAddressErrorCode EncodeP2pqpkhAddress(
    PqAddressHrp hrp,
    const uint8_t addrKeyHash256[32],
    std::string& outAddress);

PqAddressErrorCode EncodePqVaultAddress(
    PqAddressHrp hrp,
    const uint8_t ownerHash256[32],
    const uint8_t vaultHash256[32],
    std::string& outAddress);

PqAddressErrorCode PqAddressToScriptPubKey(
    const std::string& address,
    PqAddressHrp& outHrp,
    std::vector<uint8_t>& outScriptPubKey);

bool ScriptPubKeyToPqAddress(
    PqAddressHrp hrp,
    const std::vector<uint8_t>& scriptPubKey,
    std::string& outAddress);

/**
 * Segregated post-quantum witness stack for a single transaction input (`DIP-PQ-3` §2.1).
 */
struct PqInputWitness {
    std::vector<std::vector<uint8_t> > items;

    static PqInputWitness Empty();
    static PqInputWitness ForP2pqpkh(
        uint8_t schemeId,
        const std::vector<uint8_t>& pubkey,
        const std::vector<uint8_t>& signature,
        uint8_t sighashType);
    static PqInputWitness ForPqVault(
        bool isOwnerSpend,
        uint8_t schemeId,
        const std::vector<uint8_t>& pubkey,
        const std::vector<uint8_t>& signature,
        uint8_t sighashType);

    bool IsEmpty() const { return items.empty(); }
    size_t TotalItemBytes() const;
    size_t SerializedSize() const;

    std::vector<uint8_t> SerializeCanonical() const;
    static PqWitnessErrorCode DeserializeCanonical(
        const uint8_t* data,
        size_t len,
        PqInputWitness& outWitness);

    void LeafHash(uint8_t outLeafHash32[32]) const;
};

typedef PqInputWitness PqWitnessStack;

PqWitnessErrorCode ValidatePqWitnessLimits(const PqInputWitness& witness);

/**
 * Compute the 32-byte binary double-SHA256 Merkle root over per-input `PqInputWitness::LeafHash()` digests.
 * Returns 32 zero bytes when `witnesses` is empty or all input witnesses are empty.
 */
void ComputePqWitnessMerkleRoot(
    const std::vector<PqInputWitness>& witnesses,
    uint8_t outMerkleRoot32[32]);

/**
 * Compute the DIP-PQ-3 witness transaction identifier (`wtxid`, §2.4):
 * - If `witnesses` is empty or every input witness is empty: `wtxid == txid`
 * - Otherwise: `wtxid = SHA256d(txid[32] || witness_merkle_root[32])`
 */
void ComputePqWitnessId(
    const uint8_t txid32[32],
    const std::vector<PqInputWitness>& witnesses,
    uint8_t outWtxid32[32]);

/**
 * Compute the 32-byte block-level witness Merkle root over a block's transaction `wtxid`s
 * (with `wtxids[0]` replaced by 32 zero bytes for coinbase, or over the supplied 32-byte leaves).
 */
void ComputeBlockWitnessMerkleRoot(
    const std::vector<std::vector<uint8_t> >& txWtxids,
    uint8_t outBlockWitnessRoot32[32]);

/**
 * Verify a block's coinstake/header witness commitment against the computed 32-byte witness Merkle root.
 */
bool VerifyCoinstakeWitnessCommitment(
    const uint8_t headerOrCommittedRoot32[32],
    const uint8_t computedWitnessRoot32[32]);

/**
 * Compute DIP-PQ-3 transaction/block weight (`base_bytes * 4 + witness_bytes`, §2.5).
 */
size_t ComputeBlockWeight(size_t baseBytes, size_t witnessBytes);

/**
 * Enforce DIP-PQ-3 block weight (`<= 8,000,000` WU) and raw block byte cap (`<= 2,000,000` B).
 */
PqWitnessErrorCode ValidatePqBlockWeight(
    size_t baseBytes,
    size_t witnessBytes,
    size_t& outWeight);

extern "C" {

int divi_cpp_encode_pq_bech32m_address(
    uint8_t hrp_code,
    uint8_t witness_version,
    const uint8_t* program_ptr,
    size_t program_len,
    char* out_str_buf,
    size_t out_str_capacity,
    size_t* out_str_len);

int divi_cpp_decode_pq_bech32m_address(
    const char* addr_ptr,
    size_t addr_len,
    uint8_t* out_hrp_code,
    uint8_t* out_witness_version,
    uint8_t* out_program_buf,
    size_t out_program_capacity,
    size_t* out_program_len);

void divi_cpp_create_p2pqpkh_script(
    const uint8_t addr_key_hash_256[32],
    uint8_t out_script34[34]);

void divi_cpp_create_pq_staking_vault_script(
    const uint8_t owner_hash_256[32],
    const uint8_t vault_hash_256[32],
    uint8_t out_script74[74]);

int divi_cpp_extract_pq_staking_vault_hashes(
    const uint8_t* script_ptr,
    size_t script_len,
    uint8_t out_owner_hash_256[32],
    uint8_t out_vault_hash_256[32]);

void divi_cpp_compute_wtxid_from_serialized_witnesses(
    const uint8_t txid32[32],
    const uint8_t* serialized_witnesses_concat,
    const size_t* witness_lengths,
    size_t witness_count,
    uint8_t out_wtxid32[32],
    uint8_t out_witness_merkle_root32[32]);

int divi_cpp_validate_pq_block_weight(
    size_t base_bytes,
    size_t witness_bytes,
    size_t* out_weight);

} // extern "C"

#endif // DIVI_PQ_STAKING_VAULT_SCRIPT_H
