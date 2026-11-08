// Copyright (c) 2020 The DIVI Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ForkActivation.h"

#include "chain.h"
#include "primitives/block.h"

#include <unordered_map>
#include <unordered_set>

#include <Settings.h>
#include <set>
extern Settings& settings;

namespace
{
constexpr int64_t unixTimestampForDec31stMidnight = 1609459199;
constexpr int64_t unixTimestampForAugust23MidnightGMT = 1692792000;
constexpr int64_t unixTimestampForPqPhase2HybridSpork = 1830297600;
constexpr int64_t unixTimestampForPqPhase3WitnessAndVaults = 1861920000;
constexpr int64_t unixTimestampForPqPhase3BlockSig = 1861920000;
constexpr int64_t unixTimestampForPqPhase4StrictCutoff = 1893456000;
const std::set<Fork> manualOverrides = {
  Fork::CheckLockTimeVerify,
  Fork::DeprecateMasternodes,
  Fork::HybridSporkV2,
  Fork::PostQuantumWitnessAndVaults,
  Fork::PostQuantumBlockSig,
  Fork::StrictPostQuantumBlockSig,
};
/**
 * For forks that get activated at a certain block time, the associated
 * activation times.
 */
const std::unordered_map<Fork, int64_t,std::hash<int>> ACTIVATION_TIMES = {
  {Fork::TestByTimestamp, 1000000000},
  {Fork::HardenedStakeModifier, unixTimestampForDec31stMidnight},
  {Fork::UniformLotteryWinners, unixTimestampForDec31stMidnight},
  {Fork::CheckLockTimeVerify, unixTimestampForAugust23MidnightGMT},
  {Fork::DeprecateMasternodes,unixTimestampForAugust23MidnightGMT},
  {Fork::LimitTransferVerify, unixTimestampForAugust23MidnightGMT},
  {Fork::HybridSporkV2, unixTimestampForPqPhase2HybridSpork},
  {Fork::PostQuantumWitnessAndVaults, unixTimestampForPqPhase3WitnessAndVaults},
  {Fork::PostQuantumBlockSig, unixTimestampForPqPhase3BlockSig},
  {Fork::StrictPostQuantumBlockSig, unixTimestampForPqPhase4StrictCutoff}
};

const std::unordered_set<Fork, std::hash<int>> REQUIRE_BLOCK_INDEX_CONTEXT = {
  Fork::DeprecateMasternodes,
  Fork::CheckLockTimeVerify,
  Fork::LimitTransferVerify,
  Fork::HybridSporkV2,
  Fork::PostQuantumWitnessAndVaults,
  Fork::PostQuantumBlockSig,
  Fork::StrictPostQuantumBlockSig,
};

} // anonymous namespace

ActivationState::ActivationState(const CBlockIndex* pi)
  : blockIndex_(pi)
  , nTime(pi->nTime)
{}

bool ActivationState::IsActive(const Fork f) const
{
  constexpr char manualForkSettingLookup[] = "-manual_fork";
  if(settings.ParameterIsSet(manualForkSettingLookup) && manualOverrides.count(f)>0)
  {
    const int64_t timestampOverride = settings.GetArg(manualForkSettingLookup,0);
    return nTime >= timestampOverride;
  }
  const int64_t currentTime = (REQUIRE_BLOCK_INDEX_CONTEXT.count(f)>0)? blockIndex_->GetMedianTimePast(): nTime;
  const auto mit = ACTIVATION_TIMES.find(f);
  assert(mit != ACTIVATION_TIMES.end());
  return currentTime >= mit->second;
}
