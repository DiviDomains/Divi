#ifndef WALLET_RESCANNER_H
#define WALLET_RESCANNER_H
class I_BlockDataReader;
class CBlockIndex;
class CChain;
class CWallet;
class CCriticalSection;

class WalletRescanner
{
    const I_BlockDataReader& blockReader_;
    const CChain& activeChain_;
    CCriticalSection& mainCS_;
public:
    WalletRescanner(const I_BlockDataReader& blockReader, const CChain& activeChain, CCriticalSection& mainCS);
    int scanForWalletTransactions(CWallet& wallet, CBlockIndex* pindexStart, bool fUpdate);
};
#endif// WALLET_RESCANNER_H