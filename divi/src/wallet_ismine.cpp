// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2016-2017 The PIVX Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet_ismine.h"

#include "key.h"
#include "keystore.h"
#include "script/script.h"
#include "script/standard.h"

#include <boost/foreach.hpp>

using namespace std;

typedef std::vector<unsigned char> valtype;

unsigned int HaveKeys(const std::vector<valtype>& pubkeys, const CKeyStore& keystore)
{
    unsigned int nResult = 0;
    BOOST_FOREACH (const valtype& pubkey, pubkeys) {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if(keystore.HaveKey(keyID))
            ++nResult;
    }
    return nResult;
}

isminetype IsMine(const CKeyStore& keystore, const CTxDestination& dest)
{
    CScript script = GetScriptForDestination(dest);
    return IsMine(keystore, script);
}

isminetype IsMine(const CKeyStore& keystore, const CScript& scriptPubKey)
{
    VaultType vaultType;
    return IsMine(keystore,scriptPubKey,vaultType);
}

isminetype IsMine(const CKeyStore& keystore, const CScript& scriptPubKey, VaultType& vaultType)
{
    vaultType = NON_VAULT;
    if(keystore.HaveWatchOnly(scriptPubKey))
        return isminetype::ISMINE_WATCH_ONLY;
    if(keystore.HaveMultiSig(scriptPubKey))
        return isminetype::ISMINE_MULTISIG;

    std::vector<valtype> vSolutions;
    txnouttype whichType;
    if(!ExtractScriptPubKeyFormat(scriptPubKey, whichType, vSolutions)) {
        if(keystore.HaveWatchOnly(scriptPubKey))
            return isminetype::ISMINE_WATCH_ONLY;
        if(keystore.HaveMultiSig(scriptPubKey))
            return isminetype::ISMINE_MULTISIG;

        return isminetype::ISMINE_NO;
    }

    CKeyID keyID;
    switch (whichType) {
    case TX_NONSTANDARD:
    case TX_NULL_DATA:
        break;
    case TX_PUBKEY:
        keyID = CPubKey(vSolutions[0]).GetID();
        if(keystore.HaveKey(keyID))
            return isminetype::ISMINE_SPENDABLE;
        break;
    case TX_PUBKEYHASH:
        keyID = CKeyID(uint160(vSolutions[0]));
        if(keystore.HaveKey(keyID))
            return isminetype::ISMINE_SPENDABLE;
        break;
    case TX_SCRIPTHASH: {
        CScriptID scriptID = CScriptID(uint160(vSolutions[0]));
        CScript subscript;
        if(keystore.GetCScript(scriptID, subscript)) {
            isminetype ret = IsMine(keystore, subscript,vaultType);
            if(ret != isminetype::ISMINE_NO)
                return ret;
        }
        break;
    }
    case TX_VAULT: {
        keyID = CKeyID(uint160(vSolutions[0]));
        if(keystore.HaveKey(keyID))
        {
            vaultType = OWNED_VAULT;
            return isminetype::ISMINE_SPENDABLE;
        }
        keyID = CKeyID(uint160(vSolutions[1]));
        if(keystore.HaveKey(keyID))
        {
            vaultType = MANAGED_VAULT;
            CScriptID scriptID = CScriptID(scriptPubKey);
            return keystore.HaveCScript(scriptID) ? isminetype::ISMINE_SPENDABLE : isminetype::ISMINE_NO;
        }
        break;
    }
    case TX_MULTISIG: {
        // Only consider transactions "mine" if we own ALL the
        // keys involved. multi-signature transactions that are
        // partially owned (somebody else has a key that can spend
        // them) enable spend-out-from-under-you attacks, especially
        // in shared-wallet situations.
        std::vector<valtype> keys(vSolutions.begin() + 1, vSolutions.begin() + vSolutions.size() - 1);
        if(HaveKeys(keys, keystore) == keys.size())
            return isminetype::ISMINE_SPENDABLE;
        break;
    }
    }

    if(keystore.HaveWatchOnly(scriptPubKey))
        return isminetype::ISMINE_WATCH_ONLY;
    if(keystore.HaveMultiSig(scriptPubKey))
        return isminetype::ISMINE_MULTISIG;

    return isminetype::ISMINE_NO;
}
