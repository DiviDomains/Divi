// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "NotificationInterface.h"

MainNotificationSignals NotificationInterfaceRegistry::g_signals;

void NotificationInterfaceRegistry::RegisterValidationInterface(NotificationInterface* pwalletIn)
{
    registeredInterfaces.insert(pwalletIn);
    pwalletIn->RegisterWith(g_signals);
}
void NotificationInterfaceRegistry::UnregisterValidationInterface(NotificationInterface* pwalletIn)
{
    registeredInterfaces.erase(pwalletIn);
    pwalletIn->UnregisterWith(g_signals);
}

void NotificationInterfaceRegistry::UnregisterAllValidationInterfaces() {
    for(NotificationInterface* interfaceObj: registeredInterfaces)
    {
        interfaceObj->UnregisterWith(g_signals);
    }
    registeredInterfaces.clear();
}

MainNotificationSignals& NotificationInterfaceRegistry::getSignals() const
{
    return g_signals;
}

void NotificationInterface::RegisterWith(MainNotificationSignals& signals){
    signals.UpdatedBlockTip.connect(boost::bind(&NotificationInterface::UpdatedBlockTip, this, _1));
    signals.SyncTransaction.connect(boost::bind(&NotificationInterface::SyncTransaction, this, _1, _2,_3));
    signals.SetBestChain.connect(boost::bind(&NotificationInterface::SetBestChain, this, _1));
}

void NotificationInterface::UnregisterWith(MainNotificationSignals& signals) {
    signals.UpdatedBlockTip.disconnect(boost::bind(&NotificationInterface::UpdatedBlockTip, this, _1));
    signals.SetBestChain.disconnect(boost::bind(&NotificationInterface::SetBestChain, this, _1));
    signals.SyncTransaction.disconnect(boost::bind(&NotificationInterface::SyncTransaction, this, _1, _2,_3));
}
