// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX Developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletdb.h"

#include "base58.h"
#include "db.h"
#include <dbenv.h>
#include "protocol.h"
#include "serialize.h"
#include "sync.h"
#include "util.h"
#include "utiltime.h"
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/scoped_ptr.hpp>
#include <boost/thread.hpp>
#include <fstream>
#include <ValidationState.h>
#include <WalletTx.h>
#include <Settings.h>
#include <I_WalletLoader.h>
#include <MasterKey.h>
#include <keypool.h>
#include <hdchain.h>

using namespace boost;
using namespace std;

//
// CWalletDB
//

struct LockManagedWalletDBUpdatedMapping
{
    CCriticalSection cs_dbUpdateMapping;
    std::map<std::string,unsigned> walletDBUpdatedMapping;

    LockManagedWalletDBUpdatedMapping(): cs_dbUpdateMapping(), walletDBUpdatedMapping()
    {
    }

    unsigned& operator()(const std::string& walletFilename)
    {
        LOCK(cs_dbUpdateMapping);
        return walletDBUpdatedMapping[walletFilename];
    }
};

static LockManagedWalletDBUpdatedMapping lockedDBUpdateMapping;

CWalletDB::CWalletDB(
    Settings& settings,
    const std::string& dbFilename,
    const char* pszMode
    ) : settings_(settings)
    , dbFilename_(dbFilename)
    , walletDbUpdated_(lockedDBUpdateMapping(dbFilename))
    , berkleyDB_(new CDB(BerkleyDBEnvWrapper(),dbFilename))
{
    berkleyDB_->Open(settings,pszMode);
}

CWalletDB::~CWalletDB()
{
    berkleyDB_.reset();
}

bool CWalletDB::WriteName(const string& strAddress, const string& strName)
{
    walletDbUpdated_++;
    return berkleyDB_->Write(std::make_pair(string("name"), strAddress), strName);
}

bool CWalletDB::EraseName(const string& strAddress)
{
    // This should only be used for sending addresses, never for receiving addresses,
    // receiving addresses must always have an address book entry if they're not change return.
    walletDbUpdated_++;
    return berkleyDB_->Erase(std::make_pair(string("name"), strAddress));
}

bool CWalletDB::WritePurpose(const string& strAddress, const string& strPurpose)
{
    walletDbUpdated_++;
    return berkleyDB_->Write(std::make_pair(string("purpose"), strAddress), strPurpose);
}

bool CWalletDB::ErasePurpose(const string& strPurpose)
{
    walletDbUpdated_++;
    return berkleyDB_->Erase(std::make_pair(string("purpose"), strPurpose));
}

bool CWalletDB::WriteTx(uint256 hash, const CWalletTx& wtx)
{
    walletDbUpdated_++;
    return berkleyDB_->Write(std::make_pair(std::string("tx"), hash), wtx);
}

bool CWalletDB::WriteKey(const CPubKey& vchPubKey, const CPrivKey& vchPrivKey, const CKeyMetadata& keyMeta)
{
    walletDbUpdated_++;

    if (!berkleyDB_->Write(std::make_pair(std::string("keymeta"), vchPubKey),
            keyMeta, false))
        return false;

    // hash pubkey/privkey to accelerate wallet load
    std::vector<unsigned char> vchKey;
    vchKey.reserve(vchPubKey.size() + vchPrivKey.size());
    vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
    vchKey.insert(vchKey.end(), vchPrivKey.begin(), vchPrivKey.end());

    return berkleyDB_->Write(std::make_pair(std::string("key"), vchPubKey), std::make_pair(vchPrivKey, Hash(vchKey.begin(), vchKey.end())), false);
}

bool CWalletDB::WriteCryptedKey(const CPubKey& vchPubKey,
    const std::vector<unsigned char>& vchCryptedSecret,
    const CKeyMetadata& keyMeta)
{
    const bool fEraseUnencryptedKey = true;
    walletDbUpdated_++;

    if (!berkleyDB_->Write(std::make_pair(std::string("keymeta"), vchPubKey),
            keyMeta))
        return false;

    if (!berkleyDB_->Write(std::make_pair(std::string("ckey"), vchPubKey), vchCryptedSecret, false))
        return false;
    if (fEraseUnencryptedKey) {
        berkleyDB_->Erase(std::make_pair(std::string("key"), vchPubKey));
        berkleyDB_->Erase(std::make_pair(std::string("wkey"), vchPubKey));
    }
    return true;
}

bool CWalletDB::WriteMasterKey(unsigned int nID, const CMasterKey& kMasterKey)
{
    walletDbUpdated_++;
    return berkleyDB_->Write(std::make_pair(std::string("mkey"), nID), kMasterKey, true);
}

bool CWalletDB::WriteCScript(const uint160& hash, const CScript& redeemScript)
{
    walletDbUpdated_++;
    return berkleyDB_->Write(std::make_pair(std::string("cscript"), hash), redeemScript, false);
}
bool CWalletDB::EraseCScript(const uint160& hash)
{
    walletDbUpdated_++;
    return berkleyDB_->Erase(std::make_pair(std::string("cscript"), hash));
}

bool CWalletDB::WriteWatchOnly(const CScript& dest)
{
    walletDbUpdated_++;
    return berkleyDB_->Write(std::make_pair(std::string("watchs"), dest), '1');
}

bool CWalletDB::EraseWatchOnly(const CScript& dest)
{
    walletDbUpdated_++;
    return berkleyDB_->Erase(std::make_pair(std::string("watchs"), dest));
}

bool CWalletDB::WriteMultiSig(const CScript& dest)
{
    walletDbUpdated_++;
    return berkleyDB_->Write(std::make_pair(std::string("multisig"), dest), '1');
}

bool CWalletDB::EraseMultiSig(const CScript& dest)
{
    walletDbUpdated_++;
    return berkleyDB_->Erase(std::make_pair(std::string("multisig"), dest));
}

bool CWalletDB::WriteBestBlock(const CBlockLocator& locator)
{
    walletDbUpdated_++;
    return berkleyDB_->Write(std::string("bestblock"), locator);
}

bool CWalletDB::ReadBestBlock(CBlockLocator& locator)
{
    return berkleyDB_->Read(std::string("bestblock"), locator);
}

bool CWalletDB::WriteDefaultKey(const CPubKey& vchPubKey)
{
    walletDbUpdated_++;
    return berkleyDB_->Write(std::string("defaultkey"), vchPubKey);
}

bool CWalletDB::ReadPool(int64_t nPool, CKeyPool& keypool)
{
    return berkleyDB_->Read(std::make_pair(std::string("pool"), nPool), keypool);
}

bool CWalletDB::WritePool(int64_t nPool, const CKeyPool& keypool)
{
    walletDbUpdated_++;
    return berkleyDB_->Write(std::make_pair(std::string("pool"), nPool), keypool);
}

bool CWalletDB::ErasePool(int64_t nPool)
{
    walletDbUpdated_++;
    return berkleyDB_->Erase(std::make_pair(std::string("pool"), nPool));
}

bool CWalletDB::WriteMinVersion(int nVersion)
{
    return berkleyDB_->Write(std::string("minversion"), nVersion);
}

bool CWalletDB::ReadAccount(const string& strAccount, CAccount& account)
{
    account.SetNull();
    return berkleyDB_->Read(std::make_pair(string("acc"), strAccount), account);
}

bool CWalletDB::WriteAccount(const string& strAccount, const CAccount& account)
{
    return berkleyDB_->Write(std::make_pair(string("acc"), strAccount), account);
}

class CWalletScanState
{
public:
    unsigned int nKeys;
    unsigned int nCKeys;
    unsigned int nKeyMeta;
    bool fIsEncrypted;
    bool fAnyUnordered;
    int nFileVersion;
    std::vector<uint256> vWalletUpgrade;

    CWalletScanState()
    {
        nKeys = nCKeys = nKeyMeta = 0;
        fIsEncrypted = false;
        fAnyUnordered = false;
        nFileVersion = 0;
    }
};

bool ReadKeyValue(I_WalletLoader* pwallet, CDataStream& ssKey, CDataStream& ssValue, CWalletScanState& wss, string& strType, string& strErr)
{
    try {
        // Unserialize
        // Taking advantage of the fact that pair serialization
        // is just the two items serialized one after the other
        ssKey >> strType;
        if (strType == "name") {
            string strAddress;
            ssKey >> strAddress;
            if(pwallet)
            {
                ssValue >> pwallet->ModifyAddressBookData(CBitcoinAddress(strAddress).Get()).name;
            }
            else
            {
                std::string name;
                ssValue >> name;
            }
        } else if (strType == "purpose") {
            string strAddress;
            ssKey >> strAddress;
            if(pwallet)
            {
                ssValue >> pwallet->ModifyAddressBookData(CBitcoinAddress(strAddress).Get()).purpose;
            }
            else
            {
                std::string purpose;
                ssValue >> purpose;
            }
        } else if (strType == "tx") {
            uint256 hash;
            ssKey >> hash;
            CWalletTx wtx;
            ssValue >> wtx;
            CValidationState state;
            // false because there is no reason to go through the zerocoin checks for our own wallet
            if (wtx.GetHash() != hash)
                return false;

            // Undo serialize changes in 31600
            if (31404 <= wtx.fTimeReceivedIsTxTime && wtx.fTimeReceivedIsTxTime <= 31703) {
                if (!ssValue.empty()) {
                    char fTmp;
                    char fUnused;
                    ssValue >> fTmp >> fUnused >> wtx.strFromAccount;
                    strErr = strprintf("LoadWallet() upgrading tx ver=%d %d '%s' %s",
                        wtx.fTimeReceivedIsTxTime, fTmp, wtx.strFromAccount, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = fTmp;
                } else {
                    strErr = strprintf("LoadWallet() repairing tx ver=%d %s", wtx.fTimeReceivedIsTxTime, hash.ToString());
                    wtx.fTimeReceivedIsTxTime = 0;
                }
                wss.vWalletUpgrade.push_back(hash);
            }

            if (wtx.nOrderPos == -1)
                wss.fAnyUnordered = true;

            if(pwallet) pwallet->LoadWalletTransaction(wtx);
        } else if (strType == "watchs") {
            CScript script;
            ssKey >> script;
            char fYes;
            ssValue >> fYes;
            if (fYes == '1')
            {
                if(pwallet) pwallet->LoadWatchOnly(script);
            }
        } else if (strType == "multisig") {
            CScript script;
            ssKey >> script;
            char fYes;
            ssValue >> fYes;
            if (fYes == '1')
            {
                if(pwallet) pwallet->LoadMultiSig(script);
            }
        } else if (strType == "key" || strType == "wkey") {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid()) {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            CKey key;
            CPrivKey pkey;
            uint256 hash = 0;

            if (strType == "key") {
                wss.nKeys++;
                ssValue >> pkey;
            }

            // Old wallets store keys as "key" [pubkey] => [privkey]
            // ... which was slow for wallets with lots of keys, because the public key is re-derived from the private key
            // using EC operations as a checksum.
            // Newer wallets store keys as "key"[pubkey] => [privkey][hash(pubkey,privkey)], which is much faster while
            // remaining backwards-compatible.
            try {
                ssValue >> hash;
            } catch (...) {
            }

            bool fSkipCheck = false;

            if (hash != 0) {
                // hash pubkey/privkey to accelerate wallet load
                std::vector<unsigned char> vchKey;
                vchKey.reserve(vchPubKey.size() + pkey.size());
                vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
                vchKey.insert(vchKey.end(), pkey.begin(), pkey.end());

                if (Hash(vchKey.begin(), vchKey.end()) != hash) {
                    strErr = "Error reading wallet database: CPubKey/CPrivKey corrupt";
                    return false;
                }

                fSkipCheck = true;
            }

            if (!key.Load(pkey, vchPubKey, fSkipCheck)) {
                strErr = "Error reading wallet database: CPrivKey corrupt";
                return false;
            }
            if (pwallet && !pwallet->LoadKey(key, vchPubKey)) {
                strErr = "Error reading wallet database: LoadKey failed";
                return false;
            }
        } else if (strType == "mkey") {
            unsigned int nID;
            ssKey >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;
            if(pwallet)
            {
                if(!pwallet->LoadMasterKey(nID,kMasterKey))
                {
                    strErr = strprintf("Error reading wallet database: duplicate CMasterKey id %u", nID);
                }
            }
        } else if (strType == "ckey") {
            std::vector<unsigned char> vchPubKey;
            ssKey >> vchPubKey;
            std::vector<unsigned char> vchPrivKey;
            ssValue >> vchPrivKey;
            wss.nCKeys++;

            if (pwallet && !pwallet->LoadCryptedKey(vchPubKey, vchPrivKey)) {
                strErr = "Error reading wallet database: LoadCryptedKey failed";
                return false;
            }
            wss.fIsEncrypted = true;
        } else if (strType == "keymeta") {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            CKeyMetadata keyMeta;
            ssValue >> keyMeta;
            wss.nKeyMeta++;

            if(pwallet)
            {
                pwallet->LoadKeyMetadata(vchPubKey, keyMeta,true);
            }
        } else if (strType == "defaultkey") {
            CPubKey pubkey;
            ssValue >> pubkey;
            if(pwallet)
            {
                pwallet->SetDefaultKey(pubkey,false);
            }
        } else if (strType == "pool") {
            int64_t nIndex;
            ssKey >> nIndex;
            CKeyPool keypool;
            ssValue >> keypool;
            if(pwallet) pwallet->LoadKeyPool(nIndex, keypool);
        } else if (strType == "version") {
            ssValue >> wss.nFileVersion;
            if (wss.nFileVersion == 10300)
                wss.nFileVersion = 300;
        } else if (strType == "cscript") {
            uint160 hash;
            ssKey >> hash;
            CScript script;
            ssValue >> script;
            if (pwallet && !pwallet->LoadCScript(script)) {
                strErr = "Error reading wallet database: LoadCScript failed";
                return false;
            }
        } else if (strType == "hdchain")
        {
            CHDChain chain;
            ssValue >> chain;
            if (pwallet && !pwallet->SetHDChain(chain, true))
            {
                strErr = "Error reading wallet database: SetHDChain failed";
                return false;
            }
        }
        else if (strType == "chdchain")
        {
            CHDChain chain;
            ssValue >> chain;
            if (pwallet && !pwallet->SetCryptedHDChain(chain, true))
            {
                strErr = "Error reading wallet database: SetHDCryptedChain failed";
                return false;
            }
        }
        else if (strType == "hdpubkey")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;

            CHDPubKey hdPubKey;
            ssValue >> hdPubKey;

            if(vchPubKey != hdPubKey.extPubKey.pubkey)
            {
                strErr = "Error reading wallet database: CHDPubKey corrupt";
                return false;
            }
            if (pwallet && !pwallet->LoadHDPubKey(hdPubKey))
            {
                strErr = "Error reading wallet database: LoadHDPubKey failed";
                return false;
            }
        }
    } catch (...) {
        return false;
    }
    return true;
}

static bool IsKeyType(string strType)
{
    return (strType == "key" || strType == "wkey" ||
            strType == "mkey" || strType == "ckey");
}

DBErrors CWalletDB::LoadWallet(I_WalletLoader& wallet)
{
    I_WalletLoader* pwallet = &wallet;
    pwallet->SetDefaultKey(CPubKey(),false);
    CWalletScanState wss;
    bool fNoncriticalErrors = false;
    DBErrors result = DB_LOAD_OK;

    try {
        int nMinVersion = 0;
        if (berkleyDB_->Read((string) "minversion", nMinVersion)) {
            if (nMinVersion > CLIENT_VERSION)
                return DB_TOO_NEW;
            pwallet->LoadMinVersion(nMinVersion);
        }

        // Get cursor
        Dbc* pcursor = berkleyDB_->GetCursor();
        if (!pcursor) {
            LogPrintf("Error getting wallet database cursor\n");
            return DB_CORRUPT;
        }

        while (true) {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = berkleyDB_->ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0) {
                LogPrintf("Error reading next record from wallet database\n");
                return DB_CORRUPT;
            }

            // Try to be tolerant of single corrupt records:
            string strType, strErr;
            if (!ReadKeyValue(pwallet, ssKey, ssValue, wss, strType, strErr)) {
                // losing keys is considered a catastrophic error, anything else
                // we assume the user can live with:
                if (IsKeyType(strType))
                    result = DB_CORRUPT;
                else {
                    // Leave other errors alone, if we try to fix them we might make things worse.
                    fNoncriticalErrors = true; // ... but do warn the user there is something wrong.
                    if (strType == "tx")
                        // Rescan if there is a bad transaction record:
                        settings_.SoftSetBoolArg("-rescan", true);
                }
            }
            if (!strErr.empty())
                LogPrintf("%s\n", strErr);
        }
        pcursor->close();
    } catch (boost::thread_interrupted) {
        throw;
    } catch (...) {
        result = DB_CORRUPT;
    }

    if (fNoncriticalErrors && result == DB_LOAD_OK)
        result = DB_NONCRITICAL_ERROR;

    // Any wallet corruption at all: skip any rewriting or
    // upgrading, we don't want to make it worse.
    if (result != DB_LOAD_OK)
        return result;

    LogPrintf("nFileVersion = %d\n", wss.nFileVersion);

    LogPrintf("Keys: %u plaintext, %u encrypted, %u w/ metadata, %u total\n",
        wss.nKeys, wss.nCKeys, wss.nKeyMeta, wss.nKeys + wss.nCKeys);

    // nTimeFirstKey is only reliable if all keys have metadata
    if ((wss.nKeys + wss.nCKeys) != wss.nKeyMeta)
    {
        LogPrintf("Some keys lack metadata. Wallet may require a rescan\n");
    }

    pwallet->ReserializeTransactions(wss.vWalletUpgrade);

    // Rewrite encrypted wallets of versions 0.4.0 and 0.5.0rc:
    if (wss.fIsEncrypted && (wss.nFileVersion == 40000 || wss.nFileVersion == 50000))
    {
        if(CDB::Rewrite(settings_,BerkleyDBEnvWrapper(),dbFilename_, "\x04pool") )
        {
            return DB_REWRITTEN;
        }
        return DB_NEED_REWRITE;
    }

    if (wss.nFileVersion < CLIENT_VERSION) // Update
        berkleyDB_->WriteVersion(CLIENT_VERSION);

    if (wss.fAnyUnordered)
    {
        LogPrintf("Transaction reordering required during wallet load...\n");
    }
    return result;
}

void ThreadFlushWalletDB(const string& strFile)
{
    // Make this thread recognisable as the wallet flushing thread
    RenameThread("divi-wallet");

    static bool fOneThread;
    if (fOneThread)
        return;
    fOneThread = true;

    unsigned& walletDbUpdated = lockedDBUpdateMapping(strFile);
    unsigned int nLastSeen =  walletDbUpdated;
    unsigned int nLastFlushed = walletDbUpdated;
    int64_t nLastWalletUpdate = GetTime();
    static CDBEnv& bitdb_ = BerkleyDBEnvWrapper();
    while (true) {
        MilliSleep(500);

        if (nLastSeen != walletDbUpdated) {
            nLastSeen = walletDbUpdated;
            nLastWalletUpdate = GetTime();
        }

        if (nLastFlushed != walletDbUpdated && GetTime() - nLastWalletUpdate >= 2) {
            TRY_LOCK(bitdb_.cs_db, lockDb);
            if (lockDb) {
                // Don't do this if any databases are in use
                int nRefCount = 0;
                map<string, int>::iterator mi = bitdb_.mapFileUseCount.begin();
                while (mi != bitdb_.mapFileUseCount.end()) {
                    nRefCount += (*mi).second;
                    mi++;
                }

                if (nRefCount == 0) {
                    boost::this_thread::interruption_point();
                    map<string, int>::iterator mi = bitdb_.mapFileUseCount.find(strFile);
                    if (mi != bitdb_.mapFileUseCount.end()) {
                        LogPrint("db", "Flushing wallet.dat\n");
                        nLastFlushed = walletDbUpdated;
                        int64_t nStart = GetTimeMillis();

                        // Flush wallet.dat so it's self contained
                        bitdb_.CloseDb(strFile);
                        bitdb_.CheckpointLSN(strFile);

                        bitdb_.mapFileUseCount.erase(mi++);
                        LogPrint("db", "Flushed wallet.dat %dms\n", GetTimeMillis() - nStart);
                    }
                }
            }
        }
    }
}

bool BackupWallet(const std::string& walletDBFilename, const string& strDest)
{
    static CDBEnv& bitdb_ = BerkleyDBEnvWrapper();
    while (true) {
        {
            LOCK(bitdb_.cs_db);
            if (!bitdb_.mapFileUseCount.count(walletDBFilename) || bitdb_.mapFileUseCount[walletDBFilename] == 0) {
                // Flush log data to the dat file
                bitdb_.CloseDb(walletDBFilename);
                bitdb_.CheckpointLSN(walletDBFilename);
                bitdb_.mapFileUseCount.erase(walletDBFilename);

                // Copy wallet.dat
                filesystem::path pathSrc = GetDataDir() / walletDBFilename;
                filesystem::path pathDest(strDest);
                if (filesystem::is_directory(pathDest))
                    pathDest /= walletDBFilename;

                try {
#if BOOST_VERSION >= 158000
                    filesystem::copy_file(pathSrc, pathDest, filesystem::copy_option::overwrite_if_exists);
#else
                    std::ifstream src(pathSrc.string(), std::ios::binary);
                    std::ofstream dst(pathDest.string(), std::ios::binary);
                    dst << src.rdbuf();
#endif
                    LogPrintf("copied wallet.dat to %s\n", pathDest.string());
                    return true;
                } catch (const filesystem::filesystem_error& e) {
                    LogPrintf("error copying wallet.dat to %s - %s\n", pathDest.string(), e.what());
                    return false;
                }
            }
        }
        MilliSleep(100);
    }
    return false;
}

//
// Try to (very carefully!) recover wallet.dat if there is a problem.
//
bool CWalletDB::Recover(
    CDBEnv& dbenv,
    std::string filename,
    bool fOnlyKeys)
{
    // Recovery procedure:
    // move wallet.dat to wallet.timestamp.bak
    // Call Salvage with fAggressive=true to
    // get as much data as possible.
    // Rewrite salvaged data to wallet.dat
    // Set -rescan so any missing transactions will be
    // found.
    int64_t now = GetTime();
    std::string newFilename = strprintf("wallet.%d.bak", now);

    int result = dbenv.dbenv.dbrename(NULL, filename.c_str(), NULL,
        newFilename.c_str(), DB_AUTO_COMMIT);
    if (result == 0)
        LogPrintf("Renamed %s to %s\n", filename, newFilename);
    else {
        LogPrintf("Failed to rename %s to %s\n", filename, newFilename);
        return false;
    }

    std::vector<CDBEnv::KeyValPair> salvagedData;
    bool allOK = dbenv.Salvage(newFilename, true, salvagedData);
    if (salvagedData.empty()) {
        LogPrintf("Salvage(aggressive) found no records in %s.\n", newFilename);
        return false;
    }
    LogPrintf("Salvage(aggressive) found %u records\n", salvagedData.size());

    bool fSuccess = allOK;
    boost::scoped_ptr<Db> pdbCopy(new Db(&dbenv.dbenv, 0));
    int ret = pdbCopy->open(NULL, // Txn pointer
        filename.c_str(),         // Filename
        "main",                   // Logical db name
        DB_BTREE,                 // Database type
        DB_CREATE,                // Flags
        0);
    if (ret > 0) {
        LogPrintf("Cannot create database file %s\n", filename);
        return false;
    }
    CWalletScanState wss;

    DbTxn* ptxn = dbenv.TxnBegin();
    BOOST_FOREACH (CDBEnv::KeyValPair& row, salvagedData) {
        if (fOnlyKeys) {
            CDataStream ssKey(row.first, SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(row.second, SER_DISK, CLIENT_VERSION);
            string strType, strErr;
            bool fReadOK = ReadKeyValue(nullptr, ssKey, ssValue, wss, strType, strErr);
            if (!IsKeyType(strType))
                continue;
            if (!fReadOK) {
                LogPrintf("WARNING: CWalletDB::Recover skipping %s: %s\n", strType, strErr);
                continue;
            }
        }
        Dbt datKey(&row.first[0], row.first.size());
        Dbt datValue(&row.second[0], row.second.size());
        int ret2 = pdbCopy->put(ptxn, &datKey, &datValue, DB_NOOVERWRITE);
        if (ret2 > 0)
            fSuccess = false;
    }
    ptxn->commit(0);
    pdbCopy->close(0);

    return fSuccess;
}

bool CWalletDB::Recover(
    CDBEnv& dbenv,
    std::string filename)
{
    return CWalletDB::Recover(dbenv, filename, false);
}

bool CWalletDB::WriteHDChain(const CHDChain& chain)
{
    walletDbUpdated_++;
    return berkleyDB_->Write(std::string("hdchain"), chain);
}

bool CWalletDB::WriteCryptedHDChain(const CHDChain& chain)
{
    walletDbUpdated_++;

    if (!berkleyDB_->Write(std::string("chdchain"), chain))
        return false;

    berkleyDB_->Erase(std::string("hdchain"));

    return true;
}

bool CWalletDB::WriteHDPubKey(const CHDPubKey& hdPubKey, const CKeyMetadata& keyMeta)
{
    walletDbUpdated_++;

    if (!berkleyDB_->Write(std::make_pair(std::string("keymeta"), hdPubKey.extPubKey.pubkey), keyMeta, false))
        return false;

    return berkleyDB_->Write(std::make_pair(std::string("hdpubkey"), hdPubKey.extPubKey.pubkey), hdPubKey, false);
}

bool CWalletDB::TxnBegin()
{
    return berkleyDB_->TxnBegin();
}
bool CWalletDB::TxnCommit()
{
    return berkleyDB_->TxnCommit();
}
bool CWalletDB::TxnAbort()
{
    return berkleyDB_->TxnAbort();
}
bool CWalletDB::RewriteWallet()
{
    berkleyDB_->Close();
    return CDB::Rewrite(settings_,BerkleyDBEnvWrapper(),dbFilename_,NULL);
}