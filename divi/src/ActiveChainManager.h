#ifndef ACTIVE_CHAIN_MANAGER_H
#define ACTIVE_CHAIN_MANAGER_H
class CBlock;
class CValidationState;
class CBlockIndex;
class CCoinsViewCache;
class ActiveChainManager
{
public:
    static bool DisconnectBlock(CBlock& block, CValidationState& state, CBlockIndex* pindex, CCoinsViewCache& coins, bool* pfClean = nullptr);
};
#endif// ACTIVE_CHAIN_MANAGER_H