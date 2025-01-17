#include <MasternodeModule.h>

#include <utiltime.h>
#include <chrono>

#include <masternode-sync.h>
#include <masternode-payments.h>
#include <masternodeman.h>
#include <activemasternode.h>
#include <chainparams.h>
#include <ui_interface.h>
#include <Logging.h>
#include <Settings.h>
#include <masternodeconfig.h>
#include <chain.h>
#include <version.h>
#include <streams.h>
#include <net.h>
#include <Node.h>
#include <NodeStateRegistry.h>
#include <base58address.h>
#include <flat-database.h>
#include <uiMessenger.h>
#include <MasternodeNetworkMessageManager.h>
#include <MasternodePaymentData.h>
#include <MasternodeHelpers.h>
#include <MasternodeBroadcastFactory.h>
#include <netfulfilledman.h>
#include <spork.h>
#include <keystore.h>
#include <StoredMasternodeBroadcasts.h>

#include <blockmap.h>
#include <ThreadManagementHelpers.h>
#include <I_PeerSyncQueryService.h>
#include <I_Clock.h>
#include <I_BlockchainSyncQueryService.h>

bool fLiteMode = false;
extern CChain chainActive;
extern BlockMap mapBlockIndex;

class LocalClock final: public I_Clock
{
public:
    virtual int64_t getTime() const
    {
        return GetTime();
    }
};

class BlockchainSyncQueryService final: public I_BlockchainSyncQueryService
{
public:
    virtual bool isBlockchainSynced() const
    {
        return IsBlockchainSynced();
    }
};

LocalClock localClock;
MasternodeModule mnModule(localClock,GetPeerSyncQueryService(),chainActive,mapBlockIndex,GetNetworkAddressManager());

MasternodeModule::MasternodeModule(
    const I_Clock& clock,
    const I_PeerSyncQueryService& peerSyncQueryService,
    const CChain& activeChain,
    const BlockMap& blockIndexByHash,
    CAddrMan& addressManager
    ): fMasterNode_(false)
    , activeChain_(activeChain)
    , blockIndexByHash_(blockIndexByHash)
    , networkFulfilledRequestManager_(new CNetFulfilledRequestManager(clock))
    , networkMessageManager_( new MasternodeNetworkMessageManager)
    , masternodePaymentData_(new MasternodePaymentData)
    , masternodeConfig_( new CMasternodeConfig)
    , activeMasternode_(new CActiveMasternode(*masternodeConfig_, fMasterNode_))
    , masternodeSync_(new CMasternodeSync(*networkFulfilledRequestManager_,peerSyncQueryService,clock,*networkMessageManager_,*masternodePaymentData_))
    , mnodeman_(new CMasternodeMan(*networkMessageManager_,*masternodeSync_,activeChain_,blockIndexByHash_,addressManager,*activeMasternode_))
    , masternodePayments_(new CMasternodePayments(*networkFulfilledRequestManager_,*masternodePaymentData_,*networkMessageManager_,*mnodeman_,*masternodeSync_,activeChain_))
{
}

MasternodeModule::~MasternodeModule()
{
    /* The order of destruction matters, so we explicitly reset
       the unique_ptr's manually here.  */
    masternodePayments_.reset();
    mnodeman_.reset();
    masternodeSync_.reset();
    activeMasternode_.reset();
    masternodeConfig_.reset();
    masternodePaymentData_.reset();
    networkMessageManager_.reset();
    networkFulfilledRequestManager_.reset();
}

CNetFulfilledRequestManager& MasternodeModule::getNetworkFulfilledRequestManager() const
{
    return *networkFulfilledRequestManager_;
}
MasternodeNetworkMessageManager& MasternodeModule::getNetworkMessageManager() const
{
    return *networkMessageManager_;
}
MasternodePaymentData& MasternodeModule::getMasternodePaymentData() const
{
    return *masternodePaymentData_;
}
CMasternodeConfig& MasternodeModule::getMasternodeConfigurations() const
{
    return *masternodeConfig_;
}
CMasternodeMan& MasternodeModule::getMasternodeManager() const
{
    return *mnodeman_;
}
CActiveMasternode& MasternodeModule::getActiveMasternode() const
{
    return *activeMasternode_;
}
CMasternodePayments& MasternodeModule::getMasternodePayments() const
{
    return *masternodePayments_;
}
CMasternodeSync& MasternodeModule::getMasternodeSynchronization() const
{
    return *masternodeSync_;
}
StoredMasternodeBroadcasts& MasternodeModule::getStoredBroadcasts() const
{
    /* We use lazy initialisation of the stored broadcasts instance, since it
       relies on GetDataDir() and thus needs the parameters to be already
       parsed when constructed.  */
    if (storedBroadcasts_ == nullptr)
    {
        const_cast<MasternodeModule*>(this)->storedBroadcasts_.reset(
            new StoredMasternodeBroadcasts("mnbroadcasts.dat"));
    }
    return *storedBroadcasts_;
}

 bool MasternodeModule::localNodeIsAMasternode() const
 {
     return fMasterNode_;
 }
 void MasternodeModule::designateLocalNodeAsMasternode()
 {
     fMasterNode_ = true;
 }

const MasternodeModule& GetMasternodeModule()
{
    return mnModule;
}

bool SetupActiveMasternode(const Settings& settings, std::string& errorMessage)
{
    CActiveMasternode& activeMasternode = mnModule.getActiveMasternode();
    if(!activeMasternode.SetMasternodeAddress(settings.GetArg("-masternodeaddr", "")))
    {
        errorMessage = "Invalid -masternodeaddr address: " + settings.GetArg("-masternodeaddr", "");
        return false;
    }
    LogPrintf("Masternode address: %s\n", activeMasternode.service);

    if(settings.ParameterIsSet("-masternodeprivkey"))
    {
        if(!activeMasternode.SetMasternodeKey(settings.GetArg("-masternodeprivkey", "")))
        {
            errorMessage = translate("Invalid masternodeprivkey. Please see documenation.");
            return false;
        }
    }
    else
    {
        errorMessage = translate("You must specify a masternodeprivkey in the configuration. Please see documentation for help.");
        return false;
    }
    return true;
}

bool LoadMasternodeConfigurations(const Settings& settings, std::string& errorMessage)
{
    CMasternodeConfig& masternodeConfig = mnModule.getMasternodeConfigurations();
    // parse masternode.conf
    if (!masternodeConfig.read(settings,errorMessage)) {
        errorMessage="Error reading masternode configuration file: "+ errorMessage + "\n";
        return false;
    }
    return true;
}

bool InitializeMasternodeIfRequested(const Settings& settings, bool transactionIndexEnabled, std::string& errorMessage)
{
    bool enableMasternode = settings.ParameterIsSet("-masternode");
    if(enableMasternode) mnModule.designateLocalNodeAsMasternode();

    fLiteMode = settings.GetBoolArg("-litemode", false);
    if (enableMasternode && fLiteMode) {
        errorMessage = "You can not start a masternode in litemode";
        return false;
    }
    if(!LoadMasternodeConfigurations(settings,errorMessage))
    {
        return false;
    }
    if (enableMasternode && !transactionIndexEnabled)
    {
        errorMessage = "Enabling Masternode support requires turning on transaction indexing."
                         "Please add txindex=1 to your configuration and start with -reindex";
        return false;
    }
    else if (enableMasternode)
    {
        LogPrintf("IS MASTER NODE\n");
        if(!SetupActiveMasternode(settings,errorMessage))
        {
            return false;
        }
    }
    return true;
}

bool LoadMasternodeDataFromDisk(UIMessenger& uiMessenger,std::string pathToDataDir)
{
    if (!fLiteMode)
    {
        MasternodeNetworkMessageManager& networkMessageManager = mnModule.getNetworkMessageManager();
        CNetFulfilledRequestManager& networkFulfilledRequestManager = mnModule.getNetworkFulfilledRequestManager();
        std::string strDBName;

        strDBName = "netfulfilled.dat";
        uiMessenger.InitMessage("Loading fulfilled requests cache...");
        CFlatDB<CNetFulfilledRequestManager> flatdb4(strDBName, "magicFulfilledCache");
        if(!flatdb4.Load(networkFulfilledRequestManager)) {
            return uiMessenger.InitError("Failed to load fulfilled requests cache from", "\n" + pathToDataDir );
        }

        strDBName = "mncache.dat";
        uiMessenger.InitMessage("Loading masternode cache...");
        CFlatDB<MasternodeNetworkMessageManager> flatdb1(strDBName, "magicMasternodeCache");
        if(!flatdb1.Load(networkMessageManager)) {
            return uiMessenger.InitError("Failed to load masternode cache from", "\n" + pathToDataDir );
        }

        if(networkMessageManager.masternodeCount()) {
            MasternodePaymentData& masternodePaymentData = mnModule.getMasternodePaymentData();
            strDBName = "mnpayments.dat";
            uiMessenger.InitMessage("Loading masternode payment cache...");
            CFlatDB<MasternodePaymentData> flatdb2(strDBName, "magicMasternodePaymentsCache");
            if(!flatdb2.Load(masternodePaymentData)) {
                return uiMessenger.InitError("Failed to load masternode payments cache from", "\n" + pathToDataDir);
            }
        } else {
            uiMessenger.InitMessage("Masternode cache is empty, skipping payments and governance cache...");
        }
    }
    return true;
}
void SaveMasternodeDataToDisk()
{
    if(!fLiteMode)
    {
        MasternodeNetworkMessageManager& networkMessageManager = mnModule.getNetworkMessageManager();
        MasternodePaymentData& masternodePaymentData = mnModule.getMasternodePaymentData();
        CNetFulfilledRequestManager& networkFulfilledRequestManager = mnModule.getNetworkFulfilledRequestManager();
        CFlatDB<MasternodeNetworkMessageManager> flatdb1("mncache.dat", "magicMasternodeCache");
        flatdb1.Dump(networkMessageManager);
        CFlatDB<MasternodePaymentData> flatdb2("mnpayments.dat", "magicMasternodePaymentsCache");
        flatdb2.Dump(masternodePaymentData);
        CFlatDB<CNetFulfilledRequestManager> flatdb4("netfulfilled.dat", "magicFulfilledCache");
        flatdb4.Dump(networkFulfilledRequestManager);
    }
}

void ForceMasternodeResync()
{
    mnModule.getMasternodeSynchronization().Reset();
}

bool ShareMasternodePingWithPeer(CNode* peer,const uint256& inventoryHash)
{
    static const MasternodeNetworkMessageManager& networkMessageManager = mnModule.getNetworkMessageManager();
    const CMasternodePing& ping = networkMessageManager.getKnownPing(inventoryHash);
    if (ping.GetHash() == inventoryHash)
    {
        peer->PushMessage("mnp", ping);
        return true;
    }
    return false;
}

bool ShareMasternodeBroadcastWithPeer(CNode* peer,const uint256& inventoryHash)
{
    static const MasternodeNetworkMessageManager& networkMessageManager = mnModule.getNetworkMessageManager();
    const CMasternodeBroadcast& broadcast = networkMessageManager.getKnownBroadcast(inventoryHash);
    if (broadcast.GetHash() == inventoryHash)
    {
        peer->PushMessage("mnb", broadcast);
        return true;
    }
    return false;
}

bool ShareMasternodeWinnerWithPeer(CNode* peer,const uint256& inventoryHash)
{
    static const MasternodePaymentData& paymentData = mnModule.getMasternodePaymentData();
    const auto* winner = paymentData.getPaymentWinnerForHash(inventoryHash);
    if (winner != nullptr) {
        peer->PushMessage("mnw", *winner);
        return true;
    }
    return false;
}

bool MasternodePingIsKnown(const uint256& inventoryHash)
{
    static const MasternodeNetworkMessageManager& networkMessageManager = mnModule.getNetworkMessageManager();
    return networkMessageManager.pingIsKnown(inventoryHash);
}
bool MasternodeIsKnown(const uint256& inventoryHash)
{
    static const MasternodeNetworkMessageManager& networkMessageManager = mnModule.getNetworkMessageManager();
    static CMasternodeSync& masternodeSync = mnModule.getMasternodeSynchronization();
    if (networkMessageManager.broadcastIsKnown(inventoryHash))
    {
        masternodeSync.RecordMasternodeListUpdate(inventoryHash);
        return true;
    }
    return false;
}

bool MasternodeWinnerIsKnown(const uint256& inventoryHash)
{
    static const MasternodePaymentData& paymentData = mnModule.getMasternodePaymentData();
    static CMasternodeSync& masternodeSync = mnModule.getMasternodeSynchronization();
    if (paymentData.getPaymentWinnerForHash(inventoryHash) != nullptr)
    {
        masternodeSync.RecordMasternodeWinnerUpdate(inventoryHash);
        return true;
    }
    return false;
}

void ProcessMasternodeMessages(CNode* pfrom, std::string strCommand, CDataStream& vRecv)
{
    static CMasternodeMan& mnodeman = mnModule.getMasternodeManager();
    static CMasternodePayments& masternodePayments = mnModule.getMasternodePayments();
    static CMasternodeSync& masternodeSync = mnModule.getMasternodeSynchronization();
    if(!fLiteMode && IsBlockchainSynced())
    {
        masternodeSync.ProcessSyncUpdate(pfrom,strCommand,vRecv);
        mnodeman.ProcessMNBroadcastsAndPings(pfrom, strCommand, vRecv);
        masternodePayments.ProcessMasternodeWinners(pfrom, strCommand, vRecv);
    }
}

bool VoteForMasternodePayee(const CBlockIndex* pindex)
{
    static CMasternodeSync& masternodeSync = mnModule.getMasternodeSynchronization();
    static CActiveMasternode& activeMasternode = mnModule.getActiveMasternode();
    static CMasternodePayments& masternodePayments = mnModule.getMasternodePayments();
    if (fLiteMode || !masternodeSync.IsMasternodeListSynced() || !mnModule.localNodeIsAMasternode()) return false;
    constexpr int numberOfBlocksIntoTheFutureToVoteOn = 10;
    static int64_t lastBlockVotedOn = 0;
    const int64_t currentBlockToVoteFor = pindex->nHeight + numberOfBlocksIntoTheFutureToVoteOn;

    //reference node - hybrid mode

    uint256 scoringBlockHash;
    if (!GetBlockHashForScoring(scoringBlockHash, pindex, numberOfBlocksIntoTheFutureToVoteOn)) {
        LogPrint("mnpayments", "CMasternodePayments::ProcessBlock - failed to compute scoring hash\n");
        return false;
    }

    const unsigned n = masternodePayments.GetMasternodeRank(activeMasternode.vin, scoringBlockHash, ActiveProtocol(), CMasternodePayments::MNPAYMENTS_SIGNATURES_TOTAL);

    if (n == static_cast<unsigned>(-1)) {
        LogPrint("mnpayments", "CMasternodePayments::ProcessBlock - Unknown Masternode\n");
        return false;
    }

    if (n > CMasternodePayments::MNPAYMENTS_SIGNATURES_TOTAL) {
        LogPrint("mnpayments", "CMasternodePayments::ProcessBlock - Masternode not in the top %d (%d)\n", CMasternodePayments::MNPAYMENTS_SIGNATURES_TOTAL, n);
        return false;
    }

    if (currentBlockToVoteFor <= lastBlockVotedOn) return false;

    CMasternodePaymentWinner newWinner(activeMasternode.vin, currentBlockToVoteFor, scoringBlockHash);

    LogPrint("masternode","CMasternodePayments::ProcessBlock() Start nHeight %d - vin %s. \n", currentBlockToVoteFor, activeMasternode.vin.prevout.hash);

    // pay to the oldest MN that still had no payment but its input is old enough and it was active long enough
    CScript payee = masternodePayments.GetNextMasternodePayeeInQueueForPayment(pindex, numberOfBlocksIntoTheFutureToVoteOn);

    if (!payee.empty()) {
        LogPrint("masternode","CMasternodePayments::ProcessBlock() Found by FindOldestNotInVec \n");

        newWinner.AddPayee(payee);
        LogPrint("masternode","CMasternodePayments::ProcessBlock() WinnerPayee %s nHeight %d. \n", payee, newWinner.GetHeight());
    } else {
        LogPrint("masternode","CMasternodePayments::ProcessBlock() Failed to find masternode to pay\n");
    }

    LogPrint("masternode","CMasternodePayments::ProcessBlock() - Signing Winner\n");
    if(masternodePayments.CanVote(newWinner.vinMasternode.prevout,scoringBlockHash) && activeMasternode.SignMasternodeWinner(newWinner))
    {
        LogPrint("masternode","CMasternodePayments::ProcessBlock() - AddWinningMasternode\n");

        if (masternodePayments.AddWinningMasternode(newWinner)) {
            newWinner.Relay();
            lastBlockVotedOn = currentBlockToVoteFor;
            return true;
        }
    }
    else
    {
        LogPrint("masternode","%s - Error signing masternode winner\n", __func__);
    }


    return false;
}

void LockUpMasternodeCollateral(const Settings& settings, std::function<void(const COutPoint&)> walletUtxoLockingFunction)
{
    if(settings.GetBoolArg("-mnconflock", true))
    {
        CMasternodeConfig& masternodeConfig = mnModule.getMasternodeConfigurations();
        uint256 mnTxHash;
        BOOST_FOREACH (CMasternodeConfig::CMasternodeEntry mne, masternodeConfig.getEntries())
        {
            LogPrintf("  %s %s\n", mne.getTxHash(), mne.getOutputIndex());
            mnTxHash.SetHex(mne.getTxHash());
            COutPoint outpoint(mnTxHash, boost::lexical_cast<unsigned int>(mne.getOutputIndex()));
            walletUtxoLockingFunction(outpoint);
        }
    }
}


//TODO: Rename/move to core
void ThreadMasternodeBackgroundSync()
{
    if (fLiteMode) return;

    RenameThread("divi-obfuscation");

    int64_t nTimeManageStatus = 0;
    int64_t nTimeConnections = 0;

    CMasternodeSync& masternodeSync = mnModule.getMasternodeSynchronization();
    CMasternodeMan& mnodeman = mnModule.getMasternodeManager();
    CMasternodePayments& masternodePayments = mnModule.getMasternodePayments();
    while (true) {
        int64_t now;
        {
            boost::unique_lock<boost::mutex> lock(csMockTime);
            cvMockTimeChanged.wait_for(lock, boost::chrono::seconds(1));
            now = GetTime();
        }

        // try to sync from all available nodes, one step at a time
        //
        // this function keeps track of its own "last call" time and
        // ignores calls if they are too early
        if(MasternodeResyncIsRequested())
        {
            masternodeSync.Reset();
            masternodePayments.ResetRankingCache();
            FulfilledMasternodeResyncRequest();
        }
        if(!IsBlockchainSynced())
        {
            continue;
        }
        masternodeSync.Process();

        // check if we should activate or ping every few minutes,
        // start right after sync is considered to be done
        if (now >= nTimeManageStatus + MASTERNODE_PING_SECONDS) {
            nTimeManageStatus = now;
            if(mnModule.localNodeIsAMasternode()) mnodeman.ManageLocalMasternode();
        }

        if (now >= nTimeConnections + 60) {
            nTimeConnections = now;
            mnodeman.Check();
            masternodeSync.ClearTimedOutAndExpiredRequests();
            masternodePayments.PruneOldMasternodeWinnerData();
        }
    }
}
