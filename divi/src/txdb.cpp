// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2016-2017 The PIVX Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txdb.h"
#include "uint256.h"
#include <stdint.h>
#include <coins.h>
#include <boost/thread.hpp>
#include <blockFileInfo.h>
#include <blockmap.h>
#include <chainparams.h>
#include <addressindex.h>
#include <spentindex.h>
#include <DataDirectory.h>
#include <IndexDatabaseUpdates.h>

#include <boost/scoped_ptr.hpp>

using namespace std;

namespace
{

constexpr char DB_ADDRESSINDEX = 'a';
constexpr char DB_SPENTINDEX = 'p';
constexpr char DB_ADDRESSUNSPENTINDEX = 'u';
constexpr char DB_TXINDEX = 't';
constexpr char DB_BARETXIDINDEX = 'T';
constexpr char DB_COINS = 'c';
constexpr char DB_BESTBLOCKHASH = 'B';
constexpr char DB_BLOCKINDEX = 'b';
constexpr char DB_BLOCKFILEINFO = 'f';
constexpr char DB_LASTBLOCKFILE = 'l';
constexpr char DB_REINDEXINGFLAG = 'R';
constexpr char DB_NAMEDFLAG = 'F';

} // anonymous namespace


void static BatchWriteCoins(CLevelDBBatch& batch, const uint256& hash, const CCoins& coins)
{
    if (coins.IsPruned())
        batch.Erase(std::make_pair(DB_COINS, hash));
    else
        batch.Write(std::make_pair(DB_COINS, hash), coins);
}

void static BatchWriteHashBestChain(CLevelDBBatch& batch, const uint256& hash)
{
    batch.Write(DB_BESTBLOCKHASH, hash);
}

CCoinsViewDB::CCoinsViewDB(
    const BlockMap& blockIndicesByHash,
    size_t nCacheSize,
    bool fMemory,
    bool fWipe
    ): db(GetDataDir() / "chainstate", nCacheSize, fMemory, fWipe)
    , blockIndicesByHash_(blockIndicesByHash)
{
}

bool CCoinsViewDB::GetCoins(const uint256& txid, CCoins& coins) const
{
    return db.Read(std::make_pair(DB_COINS, txid), coins);
}

bool CCoinsViewDB::HaveCoins(const uint256& txid) const
{
    return db.Exists(std::make_pair(DB_COINS, txid));
}

uint256 CCoinsViewDB::GetBestBlock() const
{
    uint256 bestBlockHash;
    if (!db.Read(DB_BESTBLOCKHASH, bestBlockHash))
        return uint256(0);
    return bestBlockHash;
}

bool CCoinsViewDB::BatchWrite(CCoinsMap& mapCoins, const uint256& hashBlock)
{
    CLevelDBBatch batch;
    size_t count = 0;
    size_t changed = 0;
    for (auto it = mapCoins.begin(); it != mapCoins.end();) {
        if (it->second.flags & CCoinsCacheEntry::DIRTY) {
            BatchWriteCoins(batch, it->first, it->second.coins);
            changed++;
        }
        count++;
        CCoinsMap::iterator itOld = it++;
        mapCoins.erase(itOld);
    }
    if (hashBlock != uint256(0))
        BatchWriteHashBestChain(batch, hashBlock);

    LogPrint("coindb", "Committing %u changed transactions (out of %u) to coin database...\n", (unsigned int)changed, (unsigned int)count);
    return db.WriteBatch(batch);
}

bool CCoinsViewDB::GetStats(CCoinsStats& stats) const
{
    /* It seems that there are no "const iterators" for LevelDB.  Since we
       only need read operations on it, use a const-cast to get around
       that restriction.  */
    boost::scoped_ptr<leveldb::Iterator> pcursor(const_cast<CLevelDBWrapper*>(&db)->NewIterator());
    pcursor->SeekToFirst();

    CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
    stats.hashBlock = GetBestBlock();
    ss << stats.hashBlock;
    CAmount nTotalAmount = 0;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
            leveldb::Slice slKey = pcursor->key();
            CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(), SER_DISK, CLIENT_VERSION);
            char chType;
            ssKey >> chType;
            if (chType == DB_COINS) {
                leveldb::Slice slValue = pcursor->value();
                CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION);
                CCoins coins;
                ssValue >> coins;
                uint256 txhash;
                ssKey >> txhash;
                ss << txhash;
                ss << VARINT(coins.nVersion);
                ss << (coins.fCoinBase ? 'c' : 'n');
                ss << VARINT(coins.nHeight);
                stats.nTransactions++;
                for (unsigned int i = 0; i < coins.vout.size(); i++) {
                    const CTxOut& out = coins.vout[i];
                    if (!out.IsNull()) {
                        stats.nTransactionOutputs++;
                        ss << VARINT(i + 1);
                        ss << out;
                        nTotalAmount += out.nValue;
                    }
                }
                stats.nSerializedSize += 32 + slValue.size();
                ss << VARINT(0);
            }
            pcursor->Next();
        } catch (std::exception& e) {
            return error("%s : Deserialize or I/O error - %s", __func__, e.what());
        }
    }
    stats.nHeight = blockIndicesByHash_.find(GetBestBlock())->second->nHeight;
    stats.hashSerialized = ss.GetHash();
    stats.nTotalAmount = nTotalAmount;
    return true;
}

CBlockTreeDB::CBlockTreeDB(size_t nCacheSize, bool fMemory, bool fWipe) : CLevelDBWrapper(GetDataDir() / "blocks" / "index", nCacheSize, fMemory, fWipe)
{
}

bool CBlockTreeDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
    return Write(std::make_pair(DB_BLOCKINDEX, blockindex.GetBlockHash()), blockindex);
}

bool CBlockTreeDB::WriteBlockFileInfo(int nFile, const CBlockFileInfo& info)
{
    return Write(std::make_pair(DB_BLOCKFILEINFO, nFile), info);
}

bool CBlockTreeDB::ReadBlockFileInfo(int nFile, CBlockFileInfo& info)
{
    return Read(std::make_pair(DB_BLOCKFILEINFO, nFile), info);
}

bool CBlockTreeDB::WriteLastBlockFile(int nFile)
{
    return Write(DB_LASTBLOCKFILE, nFile);
}
bool CBlockTreeDB::ReadLastBlockFile(int& nFile)
{
    return Read(DB_LASTBLOCKFILE, nFile);
}

bool CBlockTreeDB::WriteReindexing(bool fReindexing)
{
    if (fReindexing)
        return Write(DB_REINDEXINGFLAG, '1');
    else
        return Erase(DB_REINDEXINGFLAG);
}

bool CBlockTreeDB::ReadReindexing(bool& fReindexing)
{
    fReindexing = Exists(DB_REINDEXINGFLAG);
    return true;
}

bool CBlockTreeDB::ReadTxIndex(const uint256& txid, CDiskTxPos& pos)
{
    /* This method looks up by txid or bare txid.  Both are tried, and if
       one succeeds, that must be the one.  Note that it is not possible for
       the same value to be both a bare txid and a txid (except where both
       are the same for a single transaction), as that would otherwise be
       a hash collision.  */

    if (Read(std::make_pair(DB_TXINDEX, txid), pos))
        return true;
    if (Read(std::make_pair(DB_BARETXIDINDEX, txid), pos))
        return true;

    return false;
}

bool CBlockTreeDB::WriteTxIndex(const std::vector<TxIndexEntry>& vect)
{
    CLevelDBBatch batch;
    for (const auto& entry : vect)
    {
        batch.Write(std::make_pair(DB_TXINDEX, entry.txid), entry.diskPos);
        batch.Write(std::make_pair(DB_BARETXIDINDEX, entry.bareTxid), entry.diskPos);
    }
    return WriteBatch(batch);
}

bool CBlockTreeDB::WriteFlag(const std::string& name, bool fValue)
{
    return Write(std::make_pair(DB_NAMEDFLAG, name), fValue ? '1' : '0');
}

bool CBlockTreeDB::ReadFlag(const std::string& name, bool& fValue)
{
    char ch;
    if (!Read(std::make_pair(DB_NAMEDFLAG, name), ch))
        return false;
    fValue = ch == '1';
    return true;
}

bool CBlockTreeDB::LoadBlockIndexGuts(BlockMap& blockIndicesByHash)
{
    boost::scoped_ptr<leveldb::Iterator> pcursor(NewIterator());

    CDataStream ssKeySet(SER_DISK, CLIENT_VERSION);
    ssKeySet << make_pair(DB_BLOCKINDEX, uint256(0));
    pcursor->Seek(ssKeySet.str());

    // Load mapBlockIndex
    uint256 nPreviousCheckpoint;
    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        try {
            leveldb::Slice slKey = pcursor->key();
            CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(), SER_DISK, CLIENT_VERSION);
            char chType;
            ssKey >> chType;
            if (chType == DB_BLOCKINDEX) {
                leveldb::Slice slValue = pcursor->value();
                CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION);
                CDiskBlockIndex diskindex;
                ssValue >> diskindex;

                // Construct block index object
                CBlockIndex* pindexNew = blockIndicesByHash.GetUniqueBlockIndexForHash(diskindex.GetBlockHash());
                pindexNew->pprev = blockIndicesByHash.GetUniqueBlockIndexForHash(diskindex.hashPrev);
                pindexNew->pnext = blockIndicesByHash.GetUniqueBlockIndexForHash(diskindex.hashNext);
                pindexNew->nHeight = diskindex.nHeight;
                pindexNew->nFile = diskindex.nFile;
                pindexNew->nDataPos = diskindex.nDataPos;
                pindexNew->nUndoPos = diskindex.nUndoPos;
                pindexNew->nVersion = diskindex.nVersion;
                pindexNew->hashMerkleRoot = diskindex.hashMerkleRoot;
                pindexNew->nTime = diskindex.nTime;
                pindexNew->nBits = diskindex.nBits;
                pindexNew->nNonce = diskindex.nNonce;
                pindexNew->nStatus = diskindex.nStatus;
                pindexNew->nTx = diskindex.nTx;

                //zerocoin
                pindexNew->nAccumulatorCheckpoint = diskindex.nAccumulatorCheckpoint;

                //Proof Of Stake
                pindexNew->nMint = diskindex.nMint;
                pindexNew->nMoneySupply = diskindex.nMoneySupply;
                pindexNew->nFlags = diskindex.nFlags;
                pindexNew->nStakeModifier = diskindex.nStakeModifier;
                pindexNew->prevoutStake = diskindex.prevoutStake;
                pindexNew->nStakeTime = diskindex.nStakeTime;
                pindexNew->hashProofOfStake = diskindex.hashProofOfStake;

                pindexNew->vLotteryWinnersCoinstakes = diskindex.vLotteryWinnersCoinstakes;
                pcursor->Next();
            } else {
                break; // if shutdown requested or finished loading block index
            }
        } catch (std::exception& e) {
            return error("%s : Deserialize or I/O error - %s", __func__, e.what());
        }
    }

    return true;
}

bool CBlockTreeDB::UpdateAddressUnspentIndex(const std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue > >&vect) {
    CLevelDBBatch batch;
    for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator it=vect.begin(); it!=vect.end(); it++) {
        if (it->second.IsNull()) {
            batch.Erase(make_pair(DB_ADDRESSUNSPENTINDEX, it->first));
        } else {
            batch.Write(make_pair(DB_ADDRESSUNSPENTINDEX, it->first), it->second);
        }
    }
    return WriteBatch(batch);
}

template<typename K> bool GetKey(leveldb::Slice slKey, K& key) {
    try {
        CDataStream ssKey(slKey.data(), slKey.data() + slKey.size(), SER_DISK, CLIENT_VERSION);
        ssKey >> key;
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

bool CBlockTreeDB::ReadAddressUnspentIndex(uint160 addressHash, int type,
                                           std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs) {

    boost::scoped_ptr<leveldb::Iterator> pcursor(NewIterator());

    // pcursor->Seek(make_pair(DB_ADDRESSUNSPENTINDEX, CAddressIndexIteratorKey(type, addressHash)));
    CDataStream ssKey(SER_DISK, CLIENT_VERSION);
    pair<char, CAddressIndexIteratorKey> key = make_pair(DB_ADDRESSUNSPENTINDEX, CAddressIndexIteratorKey(type, addressHash));
    ssKey.reserve(ssKey.GetSerializeSize(key));
    ssKey << key;

    leveldb::Slice slKey(&ssKey[0], ssKey.size());
    pcursor->Seek(slKey);

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char,CAddressUnspentKey> key;
        // if (pcursor->GetKey(key) && key.first == DB_ADDRESSUNSPENTINDEX && key.second.hashBytes == addressHash) {
        if (GetKey(pcursor->key(), key) && key.first == DB_ADDRESSUNSPENTINDEX && key.second.hashBytes == addressHash) {
            // CAddressUnspentValue nValue;
            //if (pcursor->GetValue(nValue)) {
            try {
                leveldb::Slice slValue = pcursor->value();
                CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION);
                CAddressUnspentValue nValue;
                ssValue >> nValue;

                unspentOutputs.push_back(make_pair(key.second, nValue));
                pcursor->Next();
            } catch (const std::exception&) {
                return error("failed to get address unspent value");
            }
        } else {
            break;
        }
    }

    return true;
}

bool CBlockTreeDB::WriteAddressIndex(const std::vector<std::pair<CAddressIndexKey, CAmount > >&vect) {
    CLevelDBBatch batch;
    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
        batch.Write(make_pair(DB_ADDRESSINDEX, it->first), it->second);
    return WriteBatch(batch);
}

bool CBlockTreeDB::EraseAddressIndex(const std::vector<std::pair<CAddressIndexKey, CAmount > >&vect) {
    CLevelDBBatch batch;
    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=vect.begin(); it!=vect.end(); it++)
        batch.Erase(make_pair(DB_ADDRESSINDEX, it->first));
    return WriteBatch(batch);
}

bool CBlockTreeDB::ReadAddressIndex(uint160 addressHash, int type,
                                    std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex,
                                    int start, int end) {

    // boost::scoped_ptr<CDBIterator> pcursor(NewIterator());
    boost::scoped_ptr<leveldb::Iterator> pcursor(NewIterator());

    CDataStream ssKey(SER_DISK, CLIENT_VERSION);

    if (start > 0 && end > 0) {
        // pcursor->Seek(make_pair(DB_ADDRESSINDEX, CAddressIndexIteratorHeightKey(type, addressHash, start)));
        pair<char, CAddressIndexIteratorHeightKey> heightKey = make_pair(DB_ADDRESSINDEX, CAddressIndexIteratorHeightKey(type, addressHash, start));
        ssKey.reserve(ssKey.GetSerializeSize(heightKey));
        ssKey << heightKey;
    } else {
        // pcursor->Seek(make_pair(DB_ADDRESSINDEX, CAddressIndexIteratorKey(type, addressHash)));
        pair<char, CAddressIndexIteratorKey> key = make_pair(DB_ADDRESSINDEX, CAddressIndexIteratorKey(type, addressHash));
        ssKey.reserve(ssKey.GetSerializeSize(key));
        ssKey << key;
    }

    leveldb::Slice slKey(&ssKey[0], ssKey.size());
    pcursor->Seek(slKey);

    while (pcursor->Valid()) {
        boost::this_thread::interruption_point();
        std::pair<char,CAddressIndexKey> key;
        // if (pcursor->GetKey(key) && key.first == DB_ADDRESSINDEX && key.second.hashBytes == addressHash) {
        if (GetKey(pcursor->key(), key) && key.first == DB_ADDRESSINDEX && key.second.hashBytes == addressHash) {
            if (end > 0 && key.second.blockHeight > end) {
                break;
            }

            try{
                leveldb::Slice slValue = pcursor->value();
                CDataStream ssValue(slValue.data(), slValue.data() + slValue.size(), SER_DISK, CLIENT_VERSION);
                CAmount nValue;
                ssValue >> nValue;

                addressIndex.push_back(make_pair(key.second, nValue));
                pcursor->Next();
            } catch (const std::exception&) {
                return error("failed to get address index value");
            }
        } else {
            break;
        }
    }

    return true;
}

bool CBlockTreeDB::ReadSpentIndex(const CSpentIndexKey &key, CSpentIndexValue &value) {
    return Read(make_pair(DB_SPENTINDEX, key), value);
}

bool CBlockTreeDB::UpdateSpentIndex(const std::vector<std::pair<CSpentIndexKey, CSpentIndexValue> >&vect) {
    CLevelDBBatch batch;
    for (std::vector<std::pair<CSpentIndexKey,CSpentIndexValue> >::const_iterator it=vect.begin(); it!=vect.end(); it++) {
        if (it->second.IsNull()) {
            batch.Erase(make_pair(DB_SPENTINDEX, it->first));
        } else {
            batch.Write(make_pair(DB_SPENTINDEX, it->first), it->second);
        }
    }
    return WriteBatch(batch);
}
