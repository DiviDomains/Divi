// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX Developers
// Copyright (c) 2017-2020 The DIVI Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_VERIFYDB_H
#define BITCOIN_VERIFYDB_H
class CCoinsView;
class CChain;
class CClientUIInterface;
class CCoinsViewCache;
class CBlockTreeDB;
class ActiveChainManager;
/** RAII wrapper for VerifyDB: Verify consistency of the block and coin databases */
class CVerifyDB
{
public:
    typedef bool (*ShutdownListener)();
private:
    const ActiveChainManager& chainManager_;
    const CChain& activeChain_;
    CClientUIInterface& clientInterface_;
    const unsigned coinsCacheSize_;
    ShutdownListener shutdownListener_;
public:
    CVerifyDB(
        const ActiveChainManager& chainManager,
        const CChain& activeChain,
        CClientUIInterface& clientInterface,
        const unsigned& coinsCacheSize,
        ShutdownListener shutdownListener);
    ~CVerifyDB();
    bool VerifyDB(const CCoinsView* coinsview, unsigned coinsTipCacheSize, int nCheckLevel, int nCheckDepth) const;
};

#endif
