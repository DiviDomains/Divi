// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2016-2017 The PIVX Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txmempool.h"

#include "clientversion.h"
#include "main.h"
#include "streams.h"
#include "Logging.h"
#include "utilmoneystr.h"
#include "version.h"
#include <UtxoCheckingAndUpdating.h>
#include <chainparams.h>

#include <boost/circular_buffer.hpp>


#include "FeeAndPriorityCalculator.h"
#include <ValidationState.h>
#include <FeePolicyEstimator.h>

using namespace std;

bool IsMemPoolHeight(unsigned coinHeight)
{
    return coinHeight == CTxMemPoolEntry::MEMPOOL_HEIGHT;
}

CTxMemPool::CTxMemPool(const CFeeRate& _minRelayFee,
                       const bool& addressIndex, const bool& spentIndex
    ): fSanityCheck(false)
    , nTransactionsUpdated(0)
    , feePolicyEstimator(new FeePolicyEstimator(25))
    , minRelayFee(_minRelayFee)
    , fAddressIndex_(addressIndex)
    , fSpentIndex_(spentIndex)
    , mapAddress()
    , mapAddressInserted()
    , mapSpent()
    , mapSpentInserted()
    , mapDeltas()
    , mapBareTxid()
    , mapTx()
    , mapNextTx()
{
    // Sanity checks off by default for performance, because otherwise
    // accepting transactions becomes O(N^2) where N is the number
    // of transactions in the pool
    // fSanityCheck = false;

    // 25 blocks is a compromise between using a lot of disk/memory and
    // trying to give accurate estimates to people who might be willing
    // to wait a day or two to save a fraction of a penny in fees.
    // Confirmation times for very-low-fee transactions that take more
    // than an hour or three to confirm are highly variable.
    // feePolicyEstimator = new CfeePolicyEstimator(25);
}

CTxMemPool::~CTxMemPool()
{
    feePolicyEstimator.reset();
}

void CTxMemPool::pruneSpent(const uint256& hashTx, CCoins& coins) const
{
    LOCK(cs);

    auto it = mapNextTx.lower_bound(COutPoint(hashTx, 0));

    // iterate over all COutPoints in mapNextTx whose hash equals the provided hashTx
    while (it != mapNextTx.end() && it->first.hash == hashTx) {
        coins.Spend(it->first.n); // and remove those outputs from coins
        it++;
    }
}

unsigned int CTxMemPool::GetTransactionsUpdated() const
{
    LOCK(cs);
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n)
{
    LOCK(cs);
    nTransactionsUpdated += n;
}


bool CTxMemPool::addUnchecked(const uint256& hash, const CTxMemPoolEntry& entry, const CCoinsViewCache& view)
{
    // Add to memory pool without checking anything.
    // Used by main.cpp AcceptToMemoryPool(), which DOES do
    // all the appropriate checks.
    LOCK(cs);
    {
        mapTx.emplace(hash,entry);
        const auto* entryInMap = &mapTx.find(hash)->second;
        const CTransaction& tx = entryInMap->GetTx();
        mapBareTxid.emplace(tx.GetBareTxid(), entryInMap);
        for (unsigned int i = 0; i < tx.vin.size(); i++)
        {
            mapNextTx[tx.vin[i].prevout] = CInPoint(&tx, i);
        }
        nTransactionsUpdated++;
        totalTxSize += entry.GetTxSize();
    }

    // Add memory address index
    if (fAddressIndex_) {
        addAddressIndex(entry, view);
    }

    // Add memory spent index
    if (fSpentIndex_) {
        addSpentIndex(entry, view);
    }

    return true;
}

void CTxMemPool::addAddressIndex(const CTxMemPoolEntry &entry, const CCoinsViewCache &view)
{
    LOCK(cs);
    const CTransaction& tx = entry.GetTx();
    std::vector<CMempoolAddressDeltaKey> inserted;

    uint256 txhash = tx.GetHash();
    for (unsigned int j = 0; j < tx.vin.size(); j++) {
        const CTxIn input = tx.vin[j];
        const CTxOut &prevout = view.GetOutputFor(input);
        if (prevout.scriptPubKey.IsPayToScriptHash()) {
            std::vector<unsigned char> hashBytes(prevout.scriptPubKey.begin()+2, prevout.scriptPubKey.begin()+22);
            CMempoolAddressDeltaKey key(2, uint160(hashBytes), txhash, j, 1);
            CMempoolAddressDelta delta(entry.GetTime(), prevout.nValue * -1, input.prevout.hash, input.prevout.n);
            mapAddress.insert(std::make_pair(key, delta));
            inserted.push_back(key);
        } else if (prevout.scriptPubKey.IsPayToPublicKeyHash()) {
            std::vector<unsigned char> hashBytes(prevout.scriptPubKey.begin()+3, prevout.scriptPubKey.begin()+23);
            CMempoolAddressDeltaKey key(1, uint160(hashBytes), txhash, j, 1);
            CMempoolAddressDelta delta(entry.GetTime(), prevout.nValue * -1, input.prevout.hash, input.prevout.n);
            mapAddress.insert(std::make_pair(key, delta));
            inserted.push_back(key);
        }
    }

    for (unsigned int k = 0; k < tx.vout.size(); k++) {
        const CTxOut &out = tx.vout[k];
        if (out.scriptPubKey.IsPayToScriptHash()) {
            std::vector<unsigned char> hashBytes(out.scriptPubKey.begin()+2, out.scriptPubKey.begin()+22);
            CMempoolAddressDeltaKey key(2, uint160(hashBytes), txhash, k, 0);
            mapAddress.insert(std::make_pair(key, CMempoolAddressDelta(entry.GetTime(), out.nValue)));
            inserted.push_back(key);
        } else if (out.scriptPubKey.IsPayToPublicKeyHash()) {
            std::vector<unsigned char> hashBytes(out.scriptPubKey.begin()+3, out.scriptPubKey.begin()+23);
            std::pair<addressDeltaMap::iterator,bool> ret;
            CMempoolAddressDeltaKey key(1, uint160(hashBytes), txhash, k, 0);
            mapAddress.insert(std::make_pair(key, CMempoolAddressDelta(entry.GetTime(), out.nValue)));
            inserted.push_back(key);
        }
    }

    mapAddressInserted.insert(std::make_pair(txhash, inserted));
}

bool CTxMemPool::getAddressIndex(const std::vector<std::pair<uint160, int> > &addresses,
                                 std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> > &results)
{
    LOCK(cs);
    for (const auto& it : addresses) {
        auto ait = mapAddress.lower_bound(CMempoolAddressDeltaKey(it.second, it.first));
        while (ait != mapAddress.end() && ait->first.addressBytes == it.first && ait->first.type == it.second) {
            results.push_back(*ait);
            ait++;
        }
    }
    return true;
}

bool CTxMemPool::removeAddressIndex(const uint256 txhash)
{
    LOCK(cs);
    addressDeltaMapInserted::iterator it = mapAddressInserted.find(txhash);

    if (it != mapAddressInserted.end()) {
        std::vector<CMempoolAddressDeltaKey> keys = (*it).second;
        for (std::vector<CMempoolAddressDeltaKey>::iterator mit = keys.begin(); mit != keys.end(); mit++) {
            mapAddress.erase(*mit);
        }
        mapAddressInserted.erase(it);
    }

    return true;
}

void CTxMemPool::addSpentIndex(const CTxMemPoolEntry &entry, const CCoinsViewCache &view)
{
    LOCK(cs);

    const CTransaction& tx = entry.GetTx();
    std::vector<CSpentIndexKey> inserted;

    uint256 txhash = tx.GetHash();
    for (unsigned int j = 0; j < tx.vin.size(); j++) {
        const CTxIn input = tx.vin[j];
        const CTxOut &prevout = view.GetOutputFor(input);
        uint160 addressHash;
        int addressType;

        if (prevout.scriptPubKey.IsPayToScriptHash()) {
            addressHash = uint160(vector<unsigned char> (prevout.scriptPubKey.begin()+2, prevout.scriptPubKey.begin()+22));
            addressType = 2;
        } else if (prevout.scriptPubKey.IsPayToPublicKeyHash()) {
            addressHash = uint160(vector<unsigned char> (prevout.scriptPubKey.begin()+3, prevout.scriptPubKey.begin()+23));
            addressType = 1;
        } else {
            addressHash.SetNull();
            addressType = 0;
        }

        CSpentIndexKey key = CSpentIndexKey(input.prevout.hash, input.prevout.n);
        CSpentIndexValue value = CSpentIndexValue(txhash, j, -1, prevout.nValue, addressType, addressHash);

        mapSpent.insert(std::make_pair(key, value));
        inserted.push_back(key);

    }

    mapSpentInserted.insert(std::make_pair(txhash, inserted));
}

bool CTxMemPool::getSpentIndex(const CSpentIndexKey &key, CSpentIndexValue &value)
{
    LOCK(cs);
    mapSpentIndex::iterator it;

    it = mapSpent.find(key);
    if (it != mapSpent.end()) {
        value = it->second;
        return true;
    }
    return false;
}

bool CTxMemPool::removeSpentIndex(const uint256& txhash)
{
    AssertLockHeld(cs);
    mapSpentIndexInserted::iterator it = mapSpentInserted.find(txhash);

    if (it != mapSpentInserted.end()) {
        std::vector<CSpentIndexKey> keys = (*it).second;
        for (std::vector<CSpentIndexKey>::iterator mit = keys.begin(); mit != keys.end(); mit++) {
            mapSpent.erase(*mit);
        }
        mapSpentInserted.erase(it);
    }

    return true;
}

void CTxMemPool::remove(const CTransaction& origTx, std::list<CTransaction>& removed, bool fRecursive)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        std::deque<uint256> txToRemove;
        txToRemove.push_back(origTx.GetHash());
        if (fRecursive && !mapTx.count(origTx.GetHash())) {
            // If recursively removing but origTx isn't in the mempool
            // be sure to remove any children that are in the pool. This can
            // happen during chain re-orgs if origTx isn't re-accepted into
            // the mempool for any reason.
            for (unsigned int i = 0; i < origTx.vout.size(); i++) {
                std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(COutPoint(origTx.GetHash(), i));
                if (it == mapNextTx.end())
                    continue;
                txToRemove.push_back(it->second.ptx->GetHash());
            }
        }
        while (!txToRemove.empty()) {
            const uint256 hash = txToRemove.front();
            txToRemove.pop_front();
            if (!mapTx.count(hash))
                continue;

            removeAddressIndex(hash);
            removeSpentIndex(hash);

            {
                const CTxMemPoolEntry& mempoolTx = mapTx.find(hash)->second;
                const CTransaction& tx = mempoolTx.GetTx();
                if (fRecursive) {
                    for (unsigned int i = 0; i < tx.vout.size(); i++) {
                        std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(COutPoint(hash, i));
                        if (it == mapNextTx.end())
                            continue;
                        txToRemove.push_back(it->second.ptx->GetHash());
                    }
                }
                mapBareTxid.erase(tx.GetBareTxid());
                for (const auto& txin : tx.vin)
                    mapNextTx.erase(txin.prevout);

                removed.push_back(tx);
                totalTxSize -= mempoolTx.GetTxSize();
            }
            mapTx.erase(hash);
            nTransactionsUpdated++;
        }
    }
}

void CTxMemPool::removeCoinbaseSpends(const CCoinsViewCache* pcoins, unsigned int nMemPoolHeight)
{
    // Remove transactions spending a coinbase which are now immature
    LOCK(cs);
    list<CTransaction> transactionsToRemove;
    for (const auto& entry : mapTx) {
        const CTransaction& tx = entry.second.GetTx();
        for (const auto& txin : tx.vin) {
            CTransaction tx2;
            if (lookupOutpoint(txin.prevout.hash, tx2))
                continue;
            const CCoins* coins = pcoins->AccessCoins(txin.prevout.hash);
            if (fSanityCheck) assert(coins);
            if (!coins || ((coins->IsCoinBase() || coins->IsCoinStake()) && nMemPoolHeight - coins->nHeight < (unsigned)Params().COINBASE_MATURITY())) {
                transactionsToRemove.push_back(tx);
                break;
            }
        }
    }
    for (const auto& tx : transactionsToRemove) {
        list<CTransaction> removed;
        remove(tx, removed, true);
    }
}

void CTxMemPool::removeConflicts(const CTransaction& tx, std::list<CTransaction>& removed)
{
    // Remove transactions which depend on inputs of tx, recursively
    list<CTransaction> result;
    LOCK(cs);
    BOOST_FOREACH (const CTxIn& txin, tx.vin) {
        std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction& txConflict = *it->second.ptx;
            if (txConflict != tx) {
                remove(txConflict, removed, true);
            }
        }
    }
}

/**
 * Called when a block is connected. Removes from mempool and updates the miner fee estimator.
 */
void CTxMemPool::removeConfirmedTransactions(const std::vector<CTransaction>& vtx, unsigned int nBlockHeight, std::list<CTransaction>& conflicts)
{
    LOCK(cs);
    std::vector<const CTxMemPoolEntry*> entries;
    BOOST_FOREACH (const CTransaction& tx, vtx) {
        uint256 hash = tx.GetHash();
        if (mapTx.count(hash))
            entries.push_back(&mapTx.find(hash)->second);
    }
    if(feePolicyEstimator) feePolicyEstimator->seenBlock(entries, nBlockHeight, minRelayFee);
    BOOST_FOREACH (const CTransaction& tx, vtx) {
        std::list<CTransaction> dummy;
        remove(tx, dummy, false);
        removeConflicts(tx, conflicts);
        ClearPrioritisation(tx.GetHash());
    }
}


void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    mapBareTxid.clear();
    totalTxSize = 0;
    ++nTransactionsUpdated;
}

void CTxMemPool::check(const CCoinsViewCache* pcoins, const BlockMap& blockIndexMap) const
{
    if (!fSanityCheck)
        return;

    LogPrint("mempool", "Checking mempool with %u transactions and %u inputs\n", (unsigned int)mapTx.size(), (unsigned int)mapNextTx.size());

    uint64_t checkTotal = 0;

    CCoinsViewCache mempoolDuplicate(const_cast<CCoinsViewCache*>(pcoins));

    LOCK(cs);
    list<const CTxMemPoolEntry*> waitingOnDependants;
    for (const auto& entry : mapTx) {
        unsigned int i = 0;
        checkTotal += entry.second.GetTxSize();
        const CTransaction& tx = entry.second.GetTx();
        bool fDependsWait = false;
        for (const auto& txin : tx.vin) {
            // Check that every mempool transaction's inputs refer to available coins, or other mempool tx's.
            CTransaction tx2;
            if (lookupOutpoint(txin.prevout.hash, tx2)) {
                assert(tx2.vout.size() > txin.prevout.n && !tx2.vout[txin.prevout.n].IsNull());
                fDependsWait = true;
            } else {
                const CCoins* coins = pcoins->AccessCoins(txin.prevout.hash);
                assert(coins && coins->IsAvailable(txin.prevout.n));
            }
            // Check whether its inputs are marked in mapNextTx.
            const auto mit = mapNextTx.find(txin.prevout);
            assert(mit != mapNextTx.end());
            assert(mit->second.ptx == &tx);
            assert(mit->second.n == i);
            i++;
        }
        if (fDependsWait)
            waitingOnDependants.push_back(&entry.second);
        else {
            CValidationState state;
            CTxUndo undo;
            assert(CheckInputs(tx, state, mempoolDuplicate, blockIndexMap, false, 0, false, NULL));
            UpdateCoinsWithTransaction(tx, mempoolDuplicate, undo, 1000000);
        }
    }
    unsigned int stepsSinceLastRemove = 0;
    while (!waitingOnDependants.empty()) {
        const CTxMemPoolEntry* entry = waitingOnDependants.front();
        waitingOnDependants.pop_front();
        CValidationState state;
        if (!mempoolDuplicate.HaveInputs(entry->GetTx())) {
            waitingOnDependants.push_back(entry);
            stepsSinceLastRemove++;
            assert(stepsSinceLastRemove < waitingOnDependants.size());
        } else {
            assert(CheckInputs(entry->GetTx(), state, mempoolDuplicate, blockIndexMap, false, 0, false, NULL));
            CTxUndo undo;
            UpdateCoinsWithTransaction(entry->GetTx(), mempoolDuplicate, undo, 1000000);
            stepsSinceLastRemove = 0;
        }
    }
    for (const auto& entry : mapNextTx) {
        const uint256 hash = entry.second.ptx->GetHash();
        const auto mit = mapTx.find(hash);
        assert(mit != mapTx.end());
        const CTransaction& tx = mit->second.GetTx();
        assert(&tx == entry.second.ptx);
        assert(tx.vin.size() > entry.second.n);
        assert(entry.first == entry.second.ptx->vin[entry.second.n].prevout);
    }

    assert(totalTxSize == checkTotal);
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (std::map<uint256, CTxMemPoolEntry>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}

bool CTxMemPool::lookup(const uint256& hash, CTransaction& result) const
{
    LOCK(cs);
    std::map<uint256, CTxMemPoolEntry>::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end()) return false;
    result = i->second.GetTx();
    return true;
}

bool CTxMemPool::lookupBareTxid(const uint256& btxid, CTransaction& result) const
{
    LOCK(cs);
    const auto mit = mapBareTxid.find(btxid);
    if (mit == mapBareTxid.end()) return false;
    result = mit->second->GetTx();
    return true;
}

bool CTxMemPool::lookupOutpoint(const uint256& hash, CTransaction& result) const
{
    /* For now (until we add the UTXO hasher and segwit light), the outpoint
       is just the transaction ID.  */
    return lookup(hash, result);
}

CFeeRate CTxMemPool::estimateFee(int nBlocks) const
{
    LOCK(cs);
    return feePolicyEstimator? feePolicyEstimator->estimateFee(nBlocks): minRelayFee;
}
double CTxMemPool::estimatePriority(int nBlocks) const
{
    LOCK(cs);
    return feePolicyEstimator? feePolicyEstimator->estimatePriority(nBlocks) : 0.0;
}

bool CTxMemPool::WriteFeeEstimates(CAutoFile& fileout) const
{
    try {
        if(!feePolicyEstimator) throw std::runtime_error("No fee policy estimator available");
        LOCK(cs);
        fileout << 120000;         // version required to read: 0.12.00 or later
        fileout << CLIENT_VERSION; // version that wrote the file
        feePolicyEstimator->Write(fileout);
    } catch (const std::exception&) {
        LogPrintf("CTxMemPool::WriteFeeEstimates() : unable to write policy estimator data (non-fatal)");
        return false;
    }
    return true;
}

bool CTxMemPool::ReadFeeEstimates(CAutoFile& filein)
{
    try {
        int nVersionRequired, nVersionThatWrote;
        filein >> nVersionRequired >> nVersionThatWrote;
        if (nVersionRequired > CLIENT_VERSION)
            return error("CTxMemPool::ReadFeeEstimates() : up-version (%d) fee estimate file", nVersionRequired);

        if(!feePolicyEstimator) throw std::runtime_error("No fee policy estimator available");

        LOCK(cs);
        feePolicyEstimator->Read(filein, minRelayFee);
    } catch (const std::exception&) {
        LogPrintf("CTxMemPool::ReadFeeEstimates() : unable to read policy estimator data (non-fatal)");
        return false;
    }
    return true;
}

void CTxMemPool::PrioritiseTransaction(const uint256 hash, const CAmount nFeeDelta)
{
    const double proxyForPriorityDelta = static_cast<double>(nFeeDelta);
    {
        LOCK(cs);
        std::pair<double, CAmount>& deltas = mapDeltas[hash];
        deltas.first += proxyForPriorityDelta;
        deltas.second += nFeeDelta;
    }
    LogPrintf("PrioritiseTransaction: %s priority += %f, fee += %d\n", hash. ToString(), proxyForPriorityDelta, FormatMoney(nFeeDelta));
}

bool CTxMemPool::IsPrioritizedTransaction(const uint256 hash)
{
    {
        LOCK(cs);
        return mapDeltas.count(hash) > 0;
    }
}


void CTxMemPool::ApplyDeltas(const uint256 hash, double& dPriorityDelta, CAmount& nFeeDelta)
{
    LOCK(cs);
    std::map<uint256, std::pair<double, CAmount> >::iterator pos = mapDeltas.find(hash);
    if (pos == mapDeltas.end())
        return;
    const std::pair<double, CAmount>& deltas = pos->second;
    dPriorityDelta += deltas.first;
    nFeeDelta += deltas.second;
}

void CTxMemPool::ClearPrioritisation(const uint256 hash)
{
    LOCK(cs);
    mapDeltas.erase(hash);
}


CCoinsViewMemPool::CCoinsViewMemPool(const CCoinsView* baseIn, const CTxMemPool& mempoolIn) : CCoinsViewBacked(baseIn), mempool(mempoolIn) {}

bool CCoinsViewMemPool::GetCoins(const uint256& txid, CCoins& coins) const
{
    // If an entry in the mempool exists, always return that one, as it's guaranteed to never
    // conflict with the underlying cache, and it cannot have pruned entries (as it contains full)
    // transactions. First checking the underlying cache risks returning a pruned entry instead.
    CTransaction tx;
    if (mempool.lookupOutpoint(txid, tx)) {
        coins = CCoins(tx, CTxMemPoolEntry::MEMPOOL_HEIGHT);
        return true;
    }
    return (CCoinsViewBacked::GetCoins(txid, coins) && !coins.IsPruned());
}

bool CCoinsViewMemPool::HaveCoins(const uint256& txid) const
{
    CTransaction dummy;
    if (mempool.lookupOutpoint(txid, dummy))
        return true;

    return CCoinsViewBacked::HaveCoins(txid);
}
bool CCoinsViewMemPool::GetCoinsAndPruneSpent(const uint256& txid,CCoins& coins) const
{
    LOCK(mempool.cs);
    if (!GetCoins(txid, coins))
        return false;
    mempool.pruneSpent(txid, coins);
    return true;
}

bool SubmitTransactionToMempool(CTxMemPool& mempool, CValidationState& state, const CTransaction& tx)
{
    constexpr const bool limitFreeTxProcessing = false;
    bool fAccepted = ::AcceptToMemoryPool(mempool, state, tx, limitFreeTxProcessing);
    if (!fAccepted)
        LogPrintf("%s : %s\n", __func__, state.GetRejectReason());
    return fAccepted;
}
bool SubmitTransactionToMempool(CTxMemPool& mempool, const CTransaction& tx)
{
    CValidationState state;
    return SubmitTransactionToMempool(mempool,state,tx);
}
