// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2016-2017 The PIVX Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXMEMPOOL_H
#define BITCOIN_TXMEMPOOL_H

#include <list>

#include "addressindex.h"
#include "spentindex.h"
#include "amount.h"
#include "FeeRate.h"
#include "coins.h"
#include "primitives/transaction.h"
#include "sync.h"
#include <MemPoolEntry.h>

class BlockMap;
class CAutoFile;

/** Fake height value used in CCoins to signify they are only in the memory pool (since 0.8) */
bool IsMemPoolHeight(unsigned coinHeight);

class FeePolicyEstimator;
/** An inpoint - a combination of a transaction and an index n into its vin */
class CInPoint
{
public:
    const CTransaction* ptx;
    uint32_t n;

    CInPoint() { SetNull(); }
    CInPoint(const CTransaction* ptxIn, uint32_t nIn)
    {
        ptx = ptxIn;
        n = nIn;
    }
    void SetNull()
    {
        ptx = NULL;
        n = (uint32_t)-1;
    }
    bool IsNull() const { return (ptx == NULL && n == (uint32_t)-1); }
};

/**
 * CTxMemPool stores valid-according-to-the-current-best-chain
 * transactions that may be included in the next block.
 *
 * Transactions are added when they are seen on the network
 * (or created by the local node), but not all transactions seen
 * are added to the pool: if a new transaction double-spends
 * an input of a transaction in the pool, it is dropped,
 * as are non-standard transactions.
 */
class CTxMemPool
{
private:
    bool fSanityCheck; //! Normally false, true if -checkmempool or -regtest
    unsigned int nTransactionsUpdated;
    std::unique_ptr<FeePolicyEstimator> feePolicyEstimator;

    const CFeeRate& minRelayFee; //! Passed to constructor to avoid dependency on main
    uint64_t totalTxSize; //! sum of all mempool tx' byte sizes

    /* The mempool reads these flags, which are passed by reference in the
       constructor and refer to the globals in main (normally at least).  */
    const bool& fAddressIndex_;
    const bool& fSpentIndex_;

    typedef std::map<CMempoolAddressDeltaKey, CMempoolAddressDelta, CMempoolAddressDeltaKeyCompare> addressDeltaMap;
    addressDeltaMap mapAddress;

    typedef std::map<uint256, std::vector<CMempoolAddressDeltaKey> > addressDeltaMapInserted;
    addressDeltaMapInserted mapAddressInserted;

    typedef std::map<CSpentIndexKey, CSpentIndexValue, CSpentIndexKeyCompare> mapSpentIndex;
    mapSpentIndex mapSpent;

    typedef std::map<uint256, std::vector<CSpentIndexKey> > mapSpentIndexInserted;
    mapSpentIndexInserted mapSpentInserted;

    std::map<uint256, std::pair<double, CAmount> > mapDeltas;

    /** Maps bare txid's of transactions to the corresponding mempool entries.
     *  This is used for lookups of outputs available in the mempool instead
     *  of mapTx in case of segwit light.  */
    std::map<uint256, const CTxMemPoolEntry*> mapBareTxid;

    void addAddressIndex(const CTxMemPoolEntry &entry, const CCoinsViewCache &view);
    bool removeAddressIndex(const uint256 txhash);

    void addSpentIndex(const CTxMemPoolEntry &entry, const CCoinsViewCache &view);
    bool removeSpentIndex(const uint256& txhash);

    void removeConflicts(const CTransaction& tx, std::list<CTransaction>& removed);
public:
    mutable CCriticalSection cs;
    std::map<uint256, CTxMemPoolEntry> mapTx;
    std::map<COutPoint, CInPoint> mapNextTx;

    explicit CTxMemPool(const CFeeRate& _minRelayFee,
                        const bool& addressIndex, const bool& spentIndex);
    ~CTxMemPool();

    /**
     * If sanity-checking is turned on, check makes sure the pool is
     * consistent (does not contain two transactions that spend the same inputs,
     * all inputs are in the mapNextTx array). If sanity-checking is turned off,
     * check does nothing.
     */
    void check(const CCoinsViewCache* pcoins, const BlockMap& blockIndexMap) const;
    void setSanityCheck(bool _fSanityCheck) { fSanityCheck = _fSanityCheck; }

    bool addUnchecked(const uint256& hash, const CTxMemPoolEntry& entry, const CCoinsViewCache& view);
    void remove(const CTransaction& tx, std::list<CTransaction>& removed, bool fRecursive = false);
    void removeCoinbaseSpends(const CCoinsViewCache* pcoins, unsigned int nMemPoolHeight);
    void removeConfirmedTransactions(const std::vector<CTransaction>& vtx, unsigned int nBlockHeight, std::list<CTransaction>& conflicts);
    void clear();
    void queryHashes(std::vector<uint256>& vtxid);
    void pruneSpent(const uint256& hash, CCoins& coins) const;
    unsigned int GetTransactionsUpdated() const;
    void AddTransactionsUpdated(unsigned int n);

    bool getAddressIndex(const std::vector<std::pair<uint160, int> > &addresses,
                         std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> > &results);

    bool getSpentIndex(const CSpentIndexKey &key, CSpentIndexValue &value);

    /** Affect CreateNewBlock prioritisation of transactions */
    bool IsPrioritizedTransaction(const uint256 hash);
    void PrioritiseTransaction(const uint256 hash, const CAmount nFeeDelta);
    void ApplyDeltas(const uint256 hash, double& dPriorityDelta, CAmount& nFeeDelta);
    void ClearPrioritisation(const uint256 hash);

    unsigned long size()
    {
        LOCK(cs);
        return mapTx.size();
    }
    uint64_t GetTotalTxSize()
    {
        LOCK(cs);
        return totalTxSize;
    }

    bool exists(const uint256& hash)
    {
        LOCK(cs);
        return (mapTx.count(hash) != 0);
    }

    bool existsBareTxid(const uint256& hash)
    {
        LOCK(cs);
        return (mapBareTxid.count(hash) != 0);
    }

    bool lookup(const uint256& hash, CTransaction& result) const;
    bool lookupBareTxid(const uint256& btxid, CTransaction& result) const;

    /** Looks up a transaction by its outpoint for spending, taking potential changes
     *  from the raw txid (e.g. segwit light) into account.  */
    bool lookupOutpoint(const uint256& hash, CTransaction& result) const;

    /** Estimate fee rate needed to get into the next nBlocks */
    CFeeRate estimateFee(int nBlocks) const;

    /** Estimate priority needed to get into the next nBlocks */
    double estimatePriority(int nBlocks) const;

    /** Write/Read estimates to disk */
    bool WriteFeeEstimates(CAutoFile& fileout) const;
    bool ReadFeeEstimates(CAutoFile& filein);
};

/**
 * CCoinsView that brings transactions from a memorypool into view.
 * It does not check for spendings by memory pool transactions.
 */
class CCoinsViewMemPool : public CCoinsViewBacked
{
protected:
    const CTxMemPool& mempool;

public:
    CCoinsViewMemPool(const CCoinsView* baseIn, const CTxMemPool& mempoolIn);
    bool GetCoins(const uint256& txid, CCoins& coins) const override;
    bool HaveCoins(const uint256& txid) const override;
    bool GetCoinsAndPruneSpent(const uint256& txid,CCoins& coins) const;
};
class CValidationState;
bool SubmitTransactionToMempool(CTxMemPool& mempool, const CTransaction& tx);
bool SubmitTransactionToMempool(CTxMemPool& mempool, CValidationState& state, const CTransaction& tx);
#endif // BITCOIN_TXMEMPOOL_H
