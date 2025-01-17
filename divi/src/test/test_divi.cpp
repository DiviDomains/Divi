// Copyright (c) 2011-2013 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BOOST_TEST_MODULE Divi Test Suite

#include <dbenv.h>
#include <chain.h>
#include <init.h>
#include "main.h"
#include "net.h"
#include "random.h"
#include "txdb.h"
#include "ui_interface.h"
#include "util.h"
#ifdef ENABLE_WALLET
#include "db.h"
#include "wallet.h"
#endif
#include <TransactionInputChecker.h>
#include <chainparams.h>
#include <Settings.h>

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

extern CClientUIInterface uiInterface;
extern CWallet* pwalletMain;
extern Settings& settings;
extern void noui_connect();
extern CBlockTreeDB* pblocktree;
extern CCoinsViewCache* pcoinsTip;
extern bool fCheckBlockIndex;
extern BlockMap mapBlockIndex;
extern int nScriptCheckThreads;
extern CChain chainActive;

struct TestingSetup {
    CCoinsViewDB *pcoinsdbview;
    boost::filesystem::path pathTemp;
    boost::thread_group threadGroup;
    CDBEnv& bitdb_;

    TestingSetup(): pcoinsdbview(nullptr), pathTemp(), threadGroup(), bitdb_(BerkleyDBEnvWrapper())
    {
        SetupEnvironment();
        fPrintToDebugLog = false; // don't want to write to debug.log file
        fCheckBlockIndex = true;
        SelectParams(CBaseChainParams::UNITTEST);
        noui_connect();
#ifdef ENABLE_WALLET
        bitdb_.MakeMock();
#endif
        pathTemp = GetTempPath() / strprintf("test_divi_%lu_%i", (unsigned long)GetTime(), (int)(GetRand(100000)));
        boost::filesystem::create_directories(pathTemp);
        settings.SetParameter("-datadir", pathTemp.string());
        pblocktree = new CBlockTreeDB(1 << 20, true);
        pcoinsdbview = new CCoinsViewDB(mapBlockIndex, 1 << 23, true);
        pcoinsTip = new CCoinsViewCache(pcoinsdbview);
        InitBlockIndex();
#ifdef ENABLE_WALLET
        InitializeWallet("wallet.dat");
        pwalletMain->LoadWallet();
        RegisterValidationInterface(pwalletMain);
#endif
        nScriptCheckThreads = 3;
        for (int i=0; i < nScriptCheckThreads-1; i++)
            threadGroup.create_thread(&TransactionInputChecker::ThreadScriptCheck);
        RegisterNodeSignals(GetNodeSignals());
        EnableUnitTestSignals();
    }
    ~TestingSetup()
    {
        threadGroup.interrupt_all();
        threadGroup.join_all();
        UnregisterNodeSignals(GetNodeSignals());
#ifdef ENABLE_WALLET
        DeallocateWallet();
#endif
        delete pcoinsTip;
        delete pcoinsdbview;
        delete pblocktree;
#ifdef ENABLE_WALLET
        bitdb_.Flush(true);
#endif
        boost::filesystem::remove_all(pathTemp);
    }
};

BOOST_GLOBAL_FIXTURE(TestingSetup);