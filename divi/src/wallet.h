// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_WALLET_H
#define BITCOIN_WALLET_H

#include <amount.h>
#include <base58address.h>
#include <pubkey.h>
#include <uint256.h>
#include <crypter.h>
#include <wallet_ismine.h>
#include <walletdb.h>
#include <ui_interface.h>
#include <FeeRate.h>
#include <boost/foreach.hpp>
#include <utilstrencodings.h>
#include <tinyformat.h>
#include <NotificationInterface.h>
#include <merkletx.h>
#include <keypool.h>
#include <reservekey.h>
#include <OutputEntry.h>
#include <Output.h>
#include <I_StakingCoinSelector.h>
#include <I_WalletLoader.h>

class I_CoinSelectionAlgorithm;
class CKeyMetadata;
class CKey;
class CBlock;
class CScript;
class CTransaction;
class CBlockIndex;
struct StakableCoin;
class WalletTransactionRecord;
class SpentOutputTracker;
class BlockMap;
class CChain;
class CCoinControl;
class COutput;
class CReserveKey;
class CScript;
class CWalletTx;
class CHDChain;
class CTxMemPool;
class CWalletDB;
class COutPoint;
class CTxIn;
class I_MerkleTxConfirmationNumberCalculator;
class I_VaultManagerDatabase;
class VaultManager;
class CBlockLocator;

bool IsFinalTx(const CTransaction& tx, const CChain& activeChain, int nBlockHeight = 0 , int64_t nBlockTime = 0);


/** (client) version numbers for particular wallet features */
enum WalletFeature {
    FEATURE_BASE = 10500, // the earliest version new wallets supports (only useful for getinfo's clientversion output)

    FEATURE_WALLETCRYPT = 40000, // wallet encryption
    FEATURE_COMPRPUBKEY = 60000, // compressed public keys
    FEATURE_HD = 120200,

    FEATURE_LATEST = 61000
};

enum AvailableCoinsType {
    ALL_SPENDABLE_COINS = 0,                    // find masternode outputs including locked ones (use with caution)
    STAKABLE_COINS = 1,                          // UTXO's that are valid for staking
    OWNED_VAULT_COINS = 2
};

/**
 * A CWallet is an extension of a keystore, which also maintains a set of transactions and balances,
 * and provides the ability to create new transactions.
 */
enum TransactionCreditFilters
{
    REQUIRE_NOTHING = 0,
    REQUIRE_UNSPENT = 1,
    REQUIRE_LOCKED = 1 << 1,
    REQUIRE_UNLOCKED  = 1 << 2,
    REQUIRE_AVAILABLE_TYPE  = 1 << 3,
};
using LockedCoinsSet = std::set<COutPoint>;
using CoinVector = std::vector<COutPoint>;
using AddressBook = std::map<CTxDestination, CAddressBookData>;
using Inputs = std::vector<CTxIn>;
using Outputs = std::vector<CTxOut>;

enum TransactionNotificationType
{
    NEW = 1 << 0,
    UPDATED = 1 << 1,
    SPEND_FROM = 1 << 3,
};
class I_WalletGuiNotifications
{
public:
    virtual ~I_WalletGuiNotifications(){}
    boost::signals2::signal<void(const CTxDestination& address, const std::string& label, bool isMine, const std::string& purpose, ChangeType status)> NotifyAddressBookChanged;
    boost::signals2::signal<void(const uint256& hashTx, int status)> NotifyTransactionChanged;
    boost::signals2::signal<void(const std::string& title, int nProgress)> ShowProgress;
    boost::signals2::signal<void(bool fHaveWatchOnly)> NotifyWatchonlyChanged;
    boost::signals2::signal<void(bool fHaveMultiSig)> NotifyMultiSigChanged;
};

class AddressBookManager
{
private:
    AddressBook mapAddressBook;
public:
    const AddressBook& GetAddressBook() const;
    AddressBook& ModifyAddressBook();
    virtual bool SetAddressBook(
        const CTxDestination& address,
        const std::string& strName,
        const std::string& purpose);

    std::set<CTxDestination> GetAccountAddresses(std::string strAccount) const;
};

class CWallet :
    public CCryptoKeyStore,
    public NotificationInterface,
    public AddressBookManager,
    public virtual I_KeypoolReserver,
    public I_WalletGuiNotifications,
    public I_StakingWallet,
    protected I_WalletLoader
{
public:
    /*
     * Main wallet lock.
     * This lock protects all the fields added by CWallet
     *   except for:
     *      fFileBacked (immutable after instantiation)
     *      strWalletFile (immutable after instantiation)
     */
    mutable CCriticalSection cs_wallet;
    bool isBackedByFile() const;
    const std::string dbFilename() const;
private:
    void SetNull();

    bool fFileBacked;
    std::string strWalletFile;
    const CChain& activeChain_;
    const BlockMap& blockIndexByHash_;
    const I_MerkleTxConfirmationNumberCalculator& confirmationNumberCalculator_;
    std::unique_ptr<I_VaultManagerDatabase> vaultDB_;
    std::unique_ptr<VaultManager> vaultManager_;
    std::unique_ptr<WalletTransactionRecord> transactionRecord_;
    std::unique_ptr<SpentOutputTracker> outputTracker_;
    std::unique_ptr<CWalletDB> pwalletdbEncryption;

    int nWalletVersion;   //! the current wallet version: clients below this version are not able to load the wallet
    int nWalletMaxVersion;//! the maximum wallet format version: memory-only variable that specifies to what version this wallet may be upgraded
    std::map<CKeyID, CKeyMetadata> mapKeyMetadata;

    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;

    LockedCoinsSet setLockedCoins;
    std::map<CKeyID, CHDPubKey> mapHdPubKeys; //<! memory map of HD extended pubkeys
    CPubKey vchDefaultKey;
    int64_t nTimeFirstKey;

    int64_t timeOfLastChainTipUpdate;
    int64_t nNextResend;
    int64_t nLastResend;
    std::set<int64_t> setInternalKeyPool;
    std::set<int64_t> setExternalKeyPool;
    bool walletStakingOnly;
    bool allowSpendingZeroConfirmationOutputs;
    int64_t defaultKeyPoolTopUp;

    bool SubmitTransactionToMemoryPool(const CWalletTx& wtx) const;

    void DeriveNewChildKey(const CKeyMetadata& metadata, CKey& secretRet, uint32_t nAccountIndex, bool fInternal /*= false*/);

    // Notification interface methods
    void SyncTransaction(const CTransaction& tx, const CBlock* pblock,const TransactionSyncType syncType) override;
    void SetBestChain(const CBlockLocator& loc) override;
    void UpdatedBlockTip(const CBlockIndex *pindex) override;

    isminetype IsMine(const CScript& scriptPubKey) const;
    isminetype IsMine(const CTxIn& txin) const;
    bool IsMine(const CTransaction& tx) const;

protected:
    // CWalletDB: load from disk methods
    void LoadWalletTransaction(const CWalletTx& wtxIn) override;
    bool LoadWatchOnly(const CScript& dest) override;
    bool LoadMinVersion(int nVersion) override;
    bool LoadMultiSig(const CScript& dest) override;
    bool LoadKey(const CKey& key, const CPubKey& pubkey) override;
    bool LoadMasterKey(unsigned int masterKeyIndex, CMasterKey& masterKey) override;
    bool LoadCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret) override;
    bool LoadKeyMetadata(const CPubKey& pubkey, const CKeyMetadata& metadata, const bool updateFirstKeyTimestamp) override;
    bool SetDefaultKey(const CPubKey& vchPubKey, bool updateDatabase) override;
    void LoadKeyPool(int nIndex, const CKeyPool &keypool) override;
    bool LoadCScript(const CScript& redeemScript) override;
    bool SetCryptedHDChain(const CHDChain& chain, bool memonly) override;
    bool LoadHDPubKey(const CHDPubKey &hdPubKey) override;
    void ReserializeTransactions(const std::vector<uint256>& transactionIDs) override;
    CAddressBookData& ModifyAddressBookData(const CTxDestination& address) override;
    bool SetHDChain(const CHDChain& chain, bool memonly) override;

public:
    explicit CWallet(
        const CChain& chain,
        const BlockMap& blockMap,
        const I_MerkleTxConfirmationNumberCalculator& confirmationNumberCalculator);
    explicit CWallet(
        const std::string& strWalletFileIn,
        const CChain& chain,
        const BlockMap& blockMap,
        const I_MerkleTxConfirmationNumberCalculator& confirmationNumberCalculator);
    ~CWallet();

    std::shared_ptr<I_WalletDatabase> GetDatabaseBackend() const;
    bool GetBlockLocator(CBlockLocator& blockLocator);
    void AddKeyMetadata(const CPubKey& pubkey, const CKeyMetadata& metadata);
    void UpdateTimeFirstKey(int64_t nCreateTime);
    void activateVaultMode();

    int64_t getTimestampOfFistKey() const;
    CKeyMetadata getKeyMetadata(const CBitcoinAddress& address) const;
    bool VerifyHDKeys() const;
    bool SetAddressBook(const CTxDestination& address, const std::string& strName, const std::string& purpose) override;

    const CPubKey& GetDefaultKey() const;
    bool InitializeDefaultKey();

    void SetDefaultKeyTopUp(int64_t keypoolTopUp);
    void toggleSpendingZeroConfirmationOutputs();

    const I_MerkleTxConfirmationNumberCalculator& getConfirmationCalculator() const;
    void UpdateBestBlockLocation();

    bool HasAgedCoins() override;
    bool SelectStakeCoins(std::set<StakableCoin>& setCoins) const override;
    bool CanStakeCoins() const override;

    bool IsSpent(const CWalletTx& wtx, unsigned int n) const;
    bool IsFullySpent(const CWalletTx& wtx) const;
    void PruneWallet();

    bool IsUnlockedForStakingOnly() const;
    bool IsFullyUnlocked() const;
    void LockFully();


    const CWalletTx* GetWalletTx(const uint256& hash) const;
    std::vector<const CWalletTx*> GetWalletTransactionReferences() const;
    void RelayWalletTransaction(const CWalletTx& walletTransaction);

    //! check whether we are allowed to upgrade (or already support) to the named feature
    bool CanSupportFeature(enum WalletFeature wf);
    bool IsAvailableForSpending(
        const CWalletTx* pcoin,
        unsigned int i,
        bool fIncludeZeroValue,
        bool& fIsSpendable,
        AvailableCoinsType coinType = AvailableCoinsType::ALL_SPENDABLE_COINS) const;
    bool SatisfiesMinimumDepthRequirements(const CWalletTx* pcoin, int& nDepth, bool fOnlyConfirmed) const;
    void AvailableCoins(
        std::vector<COutput>& vCoins,
        bool fOnlyConfirmed = true,
        bool fIncludeZeroValue = false,
        AvailableCoinsType nCoinType = ALL_SPENDABLE_COINS,
        CAmount nExactValue = CAmount(0)) const;
    std::map<CBitcoinAddress, std::vector<COutput> > AvailableCoinsByAddress(bool fConfirmed = true, CAmount maxCoinValue = 0);
    static bool SelectCoinsMinConf(
        const CWallet& wallet,
        const CAmount& nTargetValue,
        int nConfMine,
        int nConfTheirs,
        std::vector<COutput> vCoins,
        std::set<COutput>& setCoinsRet,
        CAmount& nValueRet);

    bool IsTrusted(const CWalletTx& walletTransaction) const;
    bool IsLockedCoin(const uint256& hash, unsigned int n) const;
    void LockCoin(const COutPoint& output);
    void UnlockCoin(const COutPoint& output);
    void UnlockAllCoins();
    void ListLockedCoins(CoinVector& vOutpts);

    //  keystore implementation
    // Generate a new key
    CPubKey GenerateNewKey(uint32_t nAccountIndex, bool fInternal);
    bool HaveKey(const CKeyID &address) const override;
    //! GetPubKey implementation that also checks the mapHdPubKeys
    bool GetPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const override;
    //! GetKey implementation that can derive a HD private key on the fly
    bool GetKey(const CKeyID &address, CKey& keyOut) const override;
    //! Adds a HDPubKey into the wallet(database)
    bool AddHDPubKey(const CExtPubKey &extPubKey, bool fInternal);
    //! loads a HDPubKey into the wallets memory
    //! Adds a key to the store, and saves it to disk.
    bool AddKeyPubKey(const CKey& key, const CPubKey& pubkey) override;
    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    //! Load metadata (used by LoadWallet)



    //! Adds an encrypted key to the store, and saves it to disk.
    bool AddCryptedKey(const CPubKey& vchPubKey, const std::vector<unsigned char>& vchCryptedSecret) override;
    //! Adds an encrypted key to the store, without saving it to disk (used by LoadWallet)
    bool AddCScript(const CScript& redeemScript) override;
    bool AddVault(const CScript& vaultScript, const CBlock* pblock,const CTransaction& tx);
    bool RemoveVault(const CScript& vaultScript);

    //! Adds a watch-only address to the store, and saves it to disk.
    bool AddWatchOnly(const CScript& dest) override;
    bool RemoveWatchOnly(const CScript& dest) override;
    //! Adds a watch-only address to the store, without saving it to disk (used by LoadWallet)

    //! Adds a MultiSig address to the store, and saves it to disk.
    bool AddMultiSig(const CScript& dest) override;
    bool RemoveMultiSig(const CScript& dest) override;
    //! Adds a MultiSig address to the store, without saving it to disk (used by LoadWallet)

    bool Unlock(const SecureString& strWalletPassphrase, bool stakingOnly = false);
    bool ChangeWalletPassphrase(const SecureString& strOldWalletPassphrase, const SecureString& strNewWalletPassphrase);
    bool EncryptWallet(const SecureString& strWalletPassphrase);

    void GetKeyBirthTimes(std::map<CKeyID, int64_t>& mapKeyBirth) const;

    /**
     * Get the wallet's activity log
     * @return multimap of ordered transactions and accounting entries
     * @warning Returned pointers are *only* valid within the scope of passed acentries
     */
    typedef std::multimap<int64_t, const CWalletTx*> TxItems;
    TxItems OrderedTxItems() const;

    int64_t SmartWalletTxTimestampEstimation(const CWalletTx& wtxIn);
    bool AddToWallet(const CWalletTx& wtxIn,bool blockDisconnection = false);

    bool AddToWalletIfInvolvingMe(const CTransaction& tx, const CBlock* pblock, bool fUpdate, const TransactionSyncType syncType);
    void ReacceptWalletTransactions();
    CAmount GetBalance() const;
    CAmount GetBalanceByCoinType(AvailableCoinsType coinType) const;
    CAmount GetSpendableBalance() const;
    CAmount GetStakingBalance() const;

    CAmount GetChange(const CWalletTx& walletTransaction) const;
    CAmount GetAvailableCredit(const CWalletTx& walletTransaction, bool fUseCache = true) const;
    CAmount GetImmatureCredit(const CWalletTx& walletTransaction, bool fUseCache = true) const;
    CAmount GetUnconfirmedBalance() const;
    CAmount GetImmatureBalance() const;
    std::pair<std::string,bool> CreateTransaction(
        const std::vector<std::pair<CScript, CAmount> >& vecSend,
        CWalletTx& wtxNew,
        CReserveKey& reservekey,
        const I_CoinSelectionAlgorithm* coinSelector,
        AvailableCoinsType coin_type = ALL_SPENDABLE_COINS);
    bool CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey);
    std::pair<std::string,bool> SendMoney(
        const std::vector<std::pair<CScript, CAmount> >& vecSend,
        CWalletTx& wtxNew,
        const I_CoinSelectionAlgorithm* coinSelector,
        AvailableCoinsType coin_type = ALL_SPENDABLE_COINS);
    std::string PrepareObfuscationDenominate(int minRounds, int maxRounds);

    bool NewKeyPool();
    bool TopUpKeyPool(unsigned int kpSize = 0);
    bool GetKeyFromPool(CPubKey& key, bool fInternal);
    int64_t GetOldestKeyPoolTime();
    void GetAllReserveKeys(std::set<CKeyID>& setAddress) const;
    void ReserveKeyFromKeyPool(int64_t& nIndex, CKeyPool& keypool, bool fInternal) override;
    void KeepKey(int64_t nIndex) override;
    void ReturnKey(int64_t nIndex, bool fInternal) override;
    /**
     * HD Wallet Functions
     */

    /* Returns true if HD is enabled */
    bool IsHDEnabled();
    /* Generates a new HD chain */
    void GenerateNewHDChain();
    /* Set the HD chain model (chain child index counters) */
    bool GetDecryptedHDChain(CHDChain& hdChainRet);

    std::set<std::set<CTxDestination> > GetAddressGroupings();
    std::map<CTxDestination, CAmount> GetAddressBalances();

    bool AllInputsAreMine(const CWalletTx& walletTransaction) const;
    isminetype IsMine(const CTxOut& txout) const;
    isminetype IsMine(const CTxDestination& dest) const;

    CAmount GetDebit(const CTxIn& txin, const UtxoOwnershipFilter& filter) const;
    CAmount ComputeCredit(const CTxOut& txout, const UtxoOwnershipFilter& filter) const;
    bool IsChange(const CTxOut& txout) const;
    CAmount ComputeChange(const CTxOut& txout) const;
    bool DebitsFunds(const CTransaction& tx) const;
    bool DebitsFunds(const CWalletTx& tx,const UtxoOwnershipFilter& filter) const;

    CAmount ComputeDebit(const CTransaction& tx, const UtxoOwnershipFilter& filter) const;
    CAmount GetDebit(const CWalletTx& tx, const UtxoOwnershipFilter& filter) const;
    CAmount ComputeCredit(const CWalletTx& tx, const UtxoOwnershipFilter& filter, int creditFilterFlags = REQUIRE_NOTHING) const;
    CAmount GetCredit(const CWalletTx& walletTransaction, const UtxoOwnershipFilter& filter) const;
    CAmount ComputeChange(const CTransaction& tx) const;

    DBErrors LoadWallet();

    unsigned int GetKeyPoolSize() const;

    //! signify that a particular wallet feature is now used. this may change nWalletVersion and nWalletMaxVersion if those are lower
    bool SetMinVersion(enum WalletFeature, CWalletDB* pwalletdbIn = NULL, bool fExplicit = false);

    //! change which version we're allowed to upgrade to (note that this does not immediately imply upgrading to that format)
    bool SetMaxVersion(int nVersion);

    //! get the current wallet format (the oldest client version guaranteed to understand this wallet)
    int GetVersion();

    //! Get wallet transactions that conflict with given transaction (spend same outputs)
    std::set<uint256> GetConflicts(const uint256& txid) const;
};
#endif // BITCOIN_WALLET_H
