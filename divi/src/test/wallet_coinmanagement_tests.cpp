#include <wallet.h>
#include <WalletTx.h>
#include <script/standard.h>

#include <set>
#include <stdint.h>
#include <utility>
#include <vector>

#include <boost/foreach.hpp>
#include <test/test_only.h>

#include <script/StakingVaultScript.h>
#include <random.h>
#include <chain.h>
#include <blockmap.h>
#include <test/FakeWallet.h>
#include <StakableCoin.h>
#include <I_MerkleTxConfirmationNumberCalculator.h>

class WalletCoinManagementTestFixture
{
public:
    FakeBlockIndexWithHashes fakeChain;
    FakeWallet fakeWallet;
    CWallet& wallet;

    WalletCoinManagementTestFixture()
      : fakeChain(1, 1600000000, 1), fakeWallet(fakeChain), wallet(static_cast<CWallet&>(fakeWallet))
    {
        ENTER_CRITICAL_SECTION(wallet.cs_wallet);
    }
    ~WalletCoinManagementTestFixture()
    {
        LEAVE_CRITICAL_SECTION(wallet.cs_wallet);
    }

    CScript vaultScriptAsOwner() const
    {
        CKey managerKey;
        managerKey.MakeNewKey(true);
        return CreateStakingVaultScript(
            ToByteVector(wallet.GetDefaultKey().GetID()),
            ToByteVector(managerKey.GetPubKey().GetID()));
    }
    CScript vaultScriptAsManager() const
    {
        CKey ownerKey;
        ownerKey.MakeNewKey(true);
        return CreateStakingVaultScript(
            ToByteVector(ownerKey.GetPubKey().GetID()),
            ToByteVector(wallet.GetDefaultKey().GetID()) );
    }
};

BOOST_FIXTURE_TEST_SUITE(WalletCoinManagementTests,WalletCoinManagementTestFixture)

BOOST_AUTO_TEST_CASE(willAllowSpendingUnlockedCoin)
{
    const CScript defaultScript = GetScriptForDestination(fakeWallet.getNewKey().GetID());
    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);

    bool fIsSpendable = false;
    BOOST_CHECK(wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable));
    BOOST_CHECK(fIsSpendable);
}

BOOST_AUTO_TEST_CASE(willNotAllowSpendingLockedCoin)
{
    const CScript defaultScript = GetScriptForDestination(fakeWallet.getNewKey().GetID());

    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);
    wallet.LockCoin(COutPoint(wtx.GetHash(),outputIndex));

    bool fIsSpendable = false;
    BOOST_CHECK(!wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable));
    BOOST_CHECK(!fIsSpendable);/**/
}

BOOST_AUTO_TEST_CASE(willNotAllowSpendingFromKeyOutsideWallet)
{
    CKey key; key.MakeNewKey(true);
    CPubKey nonWalletPubKey = key.GetPubKey();
    CScript defaultScript = GetScriptForDestination(nonWalletPubKey.GetID());

    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);

    bool fIsSpendable = false;
    BOOST_CHECK(!wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable));
    BOOST_CHECK(!fIsSpendable);/**/
}
BOOST_AUTO_TEST_CASE(willNotAllowSpendingFromWatchOnlyAddress)
{
    CKey key; key.MakeNewKey(true);
    CPubKey nonWalletPubKey = key.GetPubKey();
    CScript defaultScript = GetScriptForDestination(nonWalletPubKey.GetID());


    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);
    wallet.AddWatchOnly(defaultScript);

    bool fIsSpendable = false;
    BOOST_CHECK(!wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable));
    BOOST_CHECK(!fIsSpendable);/**/
}

BOOST_AUTO_TEST_CASE(willNotAllowSpendingFromWatchOnlyAddressEvenIfOwned)
{
    CScript defaultScript = GetScriptForDestination(fakeWallet.getNewKey().GetID());
    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);
    wallet.AddWatchOnly(defaultScript);

    bool fIsSpendable = false;
    BOOST_CHECK(!wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable));
    BOOST_CHECK(!fIsSpendable);/**/
}

BOOST_AUTO_TEST_CASE(willAllowSpendingLockedCoinAfterUnlock)
{
    CScript defaultScript = GetScriptForDestination(fakeWallet.getNewKey().GetID());
    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);

    wallet.LockCoin(COutPoint(wtx.GetHash(),outputIndex));
    wallet.UnlockCoin(COutPoint(wtx.GetHash(),outputIndex));

    bool fIsSpendable = false;
    BOOST_CHECK(wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable));
    BOOST_CHECK(fIsSpendable);
}

BOOST_AUTO_TEST_CASE(willMakeNoDistinctionBetweenAllCoinsAndStakableCoins)
{
    CScript defaultScript = GetScriptForDestination(fakeWallet.getNewKey().GetID());
    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);

    bool fIsSpendable = false;
    BOOST_CHECK(wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable,ALL_SPENDABLE_COINS));
    BOOST_CHECK(fIsSpendable);
    fIsSpendable = false;
    BOOST_CHECK(wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable,STAKABLE_COINS));
    BOOST_CHECK(fIsSpendable);
}

BOOST_AUTO_TEST_CASE(willDisallowSelectingVaultFundsIfManagedAndSpendableCoinsSelected)
{
    CScript defaultScript =  vaultScriptAsManager();
    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);
    wallet.AddCScript(defaultScript);

    bool fIsSpendable = false;
    BOOST_CHECK(!wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable,ALL_SPENDABLE_COINS));
}

BOOST_AUTO_TEST_CASE(willDisallowSelectingVaultFundsIfOwnerAndSpendableCoinsSelected)
{
    CScript defaultScript =  vaultScriptAsOwner();
    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);

    bool fIsSpendable = false;
    BOOST_CHECK(!wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable,ALL_SPENDABLE_COINS));
}

BOOST_AUTO_TEST_CASE(willDisallowSelectingVaultFundsIfOwnedAndStakableCoinsSelected)
{
    CScript defaultScript =  vaultScriptAsOwner();
    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);

    bool fIsSpendable = false;
    BOOST_CHECK(!wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable,STAKABLE_COINS));
}
BOOST_AUTO_TEST_CASE(willAllowSelectingVaultFundsIfManagedAndStakableCoinsSelected)
{
    CScript defaultScript =  vaultScriptAsManager();
    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);
    wallet.AddCScript(defaultScript);

    bool fIsSpendable = false;
    BOOST_CHECK(wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable,STAKABLE_COINS));
}
BOOST_AUTO_TEST_CASE(willDisallowSelectingVaultFundsIfManagedButScriptNotAdded)
{
    CScript defaultScript =  vaultScriptAsManager();
    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);

    bool fIsSpendable = false;
    BOOST_CHECK(!wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable,STAKABLE_COINS));
    BOOST_CHECK(!wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable,ALL_SPENDABLE_COINS));
    BOOST_CHECK(!wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable,OWNED_VAULT_COINS));
}

BOOST_AUTO_TEST_CASE(willDisallowSelectingVaultFundsIfManagedAndOwnedVaultCoinsSelected)
{
    CScript defaultScript =  vaultScriptAsManager();
    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);
    wallet.AddCScript(defaultScript);

    bool fIsSpendable = false;
    BOOST_CHECK(!wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable,OWNED_VAULT_COINS));
}

BOOST_AUTO_TEST_CASE(willAllowSelectingVaultFundsIfOwnerAndOwnedVaultCoinsSelected)
{
    CScript defaultScript =  vaultScriptAsOwner();
    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);

    bool fIsSpendable = false;
    BOOST_CHECK(wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable,OWNED_VAULT_COINS));
}

BOOST_AUTO_TEST_CASE(willDisallowSelectingNonVaultFundsIfOwnedVaultCoinsRequested)
{
    CScript defaultScript = GetScriptForDestination(fakeWallet.getNewKey().GetID());
    unsigned outputIndex=0;
    const CWalletTx& wtx = fakeWallet.AddDefaultTx(defaultScript,outputIndex);

    bool fIsSpendable = false;
    BOOST_CHECK(!wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable,OWNED_VAULT_COINS));
    BOOST_CHECK(!fIsSpendable);
    fIsSpendable = false;
    BOOST_CHECK(wallet.IsAvailableForSpending(&wtx,outputIndex,false,fIsSpendable,ALL_SPENDABLE_COINS));
    BOOST_CHECK(fIsSpendable);
}

BOOST_AUTO_TEST_CASE(willFindThatTransactionsByDefaultHaveNonPositiveDepth)
{
    CScript normalScript = GetScriptForDestination(wallet.GetDefaultKey().GetID());
    unsigned outputIndex=0;
    auto normalTx = fakeWallet.AddDefaultTx(normalScript,outputIndex,100*COIN);
    BOOST_CHECK_MESSAGE(wallet.getConfirmationCalculator().GetNumberOfBlockConfirmations(normalTx) < 1,"Found wallet transaction has positive depth in empty chain!");
}

BOOST_AUTO_TEST_CASE(willFindThatTransactionsWillHaveDepthAccordingToLengthOfChain)
{
    CScript normalScript = GetScriptForDestination(wallet.GetDefaultKey().GetID());
    unsigned outputIndex=0;
    const CWalletTx& normalTx = fakeWallet.AddDefaultTx(normalScript,outputIndex,100*COIN);
    fakeWallet.FakeAddToChain(normalTx);

    int someNumberOfBlocksToAdd = GetRand(25)+1;
    int startingNumberOfConfirmations = 1;
    for(int numberOfAdditionalBlocks = 0; numberOfAdditionalBlocks < someNumberOfBlocksToAdd ; ++numberOfAdditionalBlocks )
    {
        BOOST_CHECK_EQUAL(wallet.getConfirmationCalculator().GetNumberOfBlockConfirmations(normalTx),startingNumberOfConfirmations+numberOfAdditionalBlocks);
        fakeWallet.AddBlock();
    }
}

BOOST_AUTO_TEST_CASE(willReturnZeroBalancesWhenTransactionsAreUnconfirmed)
{
    CScript normalScript = GetScriptForDestination(wallet.GetDefaultKey().GetID());
    CScript ownedVaultScript = vaultScriptAsOwner();
    CScript managedVaultScript = vaultScriptAsManager();

    unsigned outputIndex=0;
    fakeWallet.AddDefaultTx(normalScript,outputIndex,100*COIN);
    fakeWallet.AddDefaultTx(ownedVaultScript,outputIndex,1000*COIN);
    fakeWallet.AddDefaultTx(managedVaultScript,outputIndex,10000*COIN);

    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetBalance(), 0,"Total balance was not the expected amount");
    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetStakingBalance(), 0,"Staking balance was not the expected amount");
    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetSpendableBalance(), 0,"Spendable balance was not the expected amount");
}

BOOST_AUTO_TEST_CASE(willReturnCorrectBalanceWhenTransactionIsConfirmed)
{
    CScript normalScript = GetScriptForDestination(wallet.GetDefaultKey().GetID());
    unsigned outputIndex=0;
    const CWalletTx& normalTx = fakeWallet.AddDefaultTx(normalScript,outputIndex,100*COIN);
    fakeWallet.FakeAddToChain(normalTx);

    BOOST_CHECK_MESSAGE(wallet.getConfirmationCalculator().GetNumberOfBlockConfirmations(normalTx) >= 1,"Transaction is not at least one block deep!");
    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetBalance(), 100*COIN,"Total balance was not the expected amount");
}

BOOST_AUTO_TEST_CASE(willFindStakingBalanceMatchesBalanceWhenOwnWalletFundsAreNotVaulted)
{
    CScript normalScript = GetScriptForDestination(wallet.GetDefaultKey().GetID());
    CScript managedVaultScript = vaultScriptAsManager();
    wallet.AddCScript(managedVaultScript);

    unsigned outputIndex=0;
    const CWalletTx& normalTx = fakeWallet.AddDefaultTx(normalScript,outputIndex,100*COIN);
    const CWalletTx& managedVaultTx = fakeWallet.AddDefaultTx(managedVaultScript,outputIndex,10000*COIN);
    fakeWallet.FakeAddToChain(normalTx);
    fakeWallet.FakeAddToChain(managedVaultTx);

    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetBalance(), 10100*COIN,"Total balance was not the expected amount");
    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetStakingBalance(), 10100*COIN,"Staking balance was not the expected amount");
}

BOOST_AUTO_TEST_CASE(willHaveAStakingBalanceFromAVaultThatIsntSpendable)
{
    CScript managedVaultScript = vaultScriptAsManager();
    wallet.AddCScript(managedVaultScript);

    unsigned outputIndex=0;
    const CWalletTx& managedVaultTx = fakeWallet.AddDefaultTx(managedVaultScript,outputIndex,10000*COIN);
    fakeWallet.FakeAddToChain(managedVaultTx);

    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetBalance(), 10000*COIN,"Total balance was not the expected amount");
    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetStakingBalance(), 10000*COIN,"Staking balance was not the expected amount");
    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetSpendableBalance(), 0*COIN,"Spendable balance was not the expected amount");
}

BOOST_AUTO_TEST_CASE(willTreatOwnedVaultAsUnspendableButWillRecordBalance)
{
    CScript ownedVaultScript = vaultScriptAsOwner();

    unsigned outputIndex=0;
    const CWalletTx& ownedVaultTx = fakeWallet.AddDefaultTx(ownedVaultScript,outputIndex,10000*COIN);
    fakeWallet.FakeAddToChain(ownedVaultTx);

    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetBalance(), 10000*COIN,"Total balance was not the expected amount");
    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetStakingBalance(), 0*COIN,"Staking balance was not the expected amount");
    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetSpendableBalance(), 0*COIN,"Spendable balance was not the expected amount");
}

BOOST_AUTO_TEST_CASE(willEnsureBalancesAreAsExpected)
{
    CScript normalScript = GetScriptForDestination(wallet.GetDefaultKey().GetID());
    CScript ownedVaultScript = vaultScriptAsOwner();
    CScript managedVaultScript = vaultScriptAsManager();
    wallet.AddCScript(managedVaultScript);


    CAmount normalTxValue = (GetRand(1000)+1)*COIN;
    CAmount ownedVaultTxValue = (GetRand(1000)+1)*COIN;
    CAmount managedVaultTxValue = (GetRand(1000)+1)*COIN;
    CAmount totalBalance = normalTxValue + ownedVaultTxValue + managedVaultTxValue;

    unsigned outputIndex=0;
    const CWalletTx& normalTx = fakeWallet.AddDefaultTx(normalScript,outputIndex,normalTxValue);
    const CWalletTx& ownedVaultTx = fakeWallet.AddDefaultTx(ownedVaultScript,outputIndex,ownedVaultTxValue);
    const CWalletTx& managedVaultTx = fakeWallet.AddDefaultTx(managedVaultScript,outputIndex,managedVaultTxValue);

    fakeWallet.FakeAddToChain(normalTx);
    fakeWallet.FakeAddToChain(ownedVaultTx);
    fakeWallet.FakeAddToChain(managedVaultTx);

    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetBalance(), totalBalance,"Total balance was not the expected amount");
    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetStakingBalance(), normalTxValue+managedVaultTxValue,"Staking balance was not the expected amount");
    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetSpendableBalance(), normalTxValue,"Spendable balance was not the expected amount");
    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetBalanceByCoinType(OWNED_VAULT_COINS), ownedVaultTxValue,"Owned vault balance was not the expected amount");
}

BOOST_AUTO_TEST_CASE(willEnsureLockedCoinsDoNotCountTowardStakableBalance)
{
    CScript normalScript = GetScriptForDestination(wallet.GetDefaultKey().GetID());
    CScript ownedVaultScript = vaultScriptAsOwner();
    CScript managedVaultScript = vaultScriptAsManager();
    wallet.AddCScript(managedVaultScript);


    CAmount firstNormalTxValue = (GetRand(1000)+1)*COIN;
    CAmount secondNormalTxValue = (GetRand(1000)+1)*COIN;

    unsigned firstTxOutputIndex=0;
    const CWalletTx& firstNormalTx = fakeWallet.AddDefaultTx(normalScript,firstTxOutputIndex,firstNormalTxValue);
    unsigned secondTxOutputIndex=0;
    const CWalletTx& secondNormalTx = fakeWallet.AddDefaultTx(normalScript,secondTxOutputIndex,secondNormalTxValue);
    fakeWallet.FakeAddToChain(firstNormalTx);
    fakeWallet.FakeAddToChain(secondNormalTx);

    wallet.LockCoin(COutPoint(firstNormalTx.GetHash(),firstTxOutputIndex));

    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetBalance(), firstNormalTxValue+secondNormalTxValue,"Total balance was not the expected amount");
    BOOST_CHECK_EQUAL_MESSAGE(wallet.GetStakingBalance(), secondNormalTxValue,"Staking balance was not the expected amount");
}


BOOST_AUTO_TEST_CASE(willEnsureStakingBalanceAndTotalBalanceAgreeEvenIfTxsBelongToCommonBlock)
{
    CScript normalScript = GetScriptForDestination(wallet.GetDefaultKey().GetID());

    CAmount firstNormalTxValue = (GetRand(1000)+1)*COIN;
    CAmount secondNormalTxValue = (GetRand(1000)+1)*COIN;

    unsigned firstTxOutputIndex=0;
    const CWalletTx& firstNormalTx = fakeWallet.AddDefaultTx(normalScript,firstTxOutputIndex,firstNormalTxValue);
    unsigned secondTxOutputIndex=0;
    const CWalletTx& secondNormalTx = fakeWallet.AddDefaultTx(normalScript,secondTxOutputIndex,secondNormalTxValue);
    fakeWallet.FakeAddToChain(firstNormalTx);
    fakeWallet.FakeAddToChain(secondNormalTx);

    std::set<StakableCoin> stakableCoins;
    stakableCoins.insert(StakableCoin(firstNormalTx,COutPoint(firstNormalTx.GetHash(),firstTxOutputIndex),firstNormalTx.hashBlock));
    stakableCoins.insert(StakableCoin(secondNormalTx,COutPoint(secondNormalTx.GetHash(),secondTxOutputIndex),secondNormalTx.hashBlock));
    BOOST_CHECK_EQUAL_MESSAGE(stakableCoins.size(),2,"Missing coins in the stakable set");
}

BOOST_AUTO_TEST_SUITE_END()
