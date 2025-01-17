#!/usr/bin/env python3
# Copyright (c) 2020 The DIVI developers
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Tests detection of vault transactions in spent and address indexing

from test_framework import BitcoinTestFramework
from authproxy import JSONRPCException
from messages import *
from util import *
from script import *
from PowToPosTransition import createPoSStacks, generatePoSBlocks

import codecs
from decimal import Decimal
import random

class VaultUtxoIndexing (BitcoinTestFramework):

    def setup_network (self, split=False):
        self.config_args = ["-debug","-spentindex=1","-addressindex=1"]
        staker_config_args = self.config_args + ["-vault=1"]
        self.nodes = start_nodes (2, self.options.tmpdir, extra_args=[self.config_args,staker_config_args])
        connect_nodes_bi(self.nodes,0,1)
        self.owner = self.nodes[0]
        self.staker = self.nodes[1]
        self.is_network_split = False

    def create_vault_stacks(self):
        self.owner.setgenerate(True,50)
        self.owner_vault_addresses = []
        self.vault_data = []
        print("Creating vault utxos...")
        for _ in range(3):
            owner_node_address = self.owner.getnewaddress()
            vault_node_address = self.staker.getnewaddress()
            vault_encoding = owner_node_address+":"+vault_node_address
            vaulting_result = self.owner.fundvault(vault_encoding,10000.0)

            print("Node balance: {} | New vault: {}".format(self.owner.getbalance(),vaulting_result))
            self.vault_data.append(vaulting_result)
            self.owner_vault_addresses.append(owner_node_address)

        self.owner.setgenerate(True,50)
        self.vault_hashes = []
        for vault_datum in self.vault_data:
            assert self.staker.addvault(vault_datum["vault"],vault_datum["txhash"])["succeeded"]
            self.vault_hashes.append(vault_datum["txhash"])
        sync_blocks(self.nodes)

    def run_test (self):
        self.create_vault_stacks()

        # Check that vault utxos are found when querying by address
        for addr in self.owner_vault_addresses:
            utxos = self.owner.getaddressutxos(addr, True)
            assert_equal(len(utxos),1)
            assert_equal(self.owner.getaddressbalance({"addresses":[addr]},True)["balance"],10000*COIN)

            balance_updates = self.owner.getaddressdeltas({"addresses":[addr],"start": int(1),"end":int(52)},True)
            assert_equal(balance_updates[0]["satoshis"], 10000*COIN)

            balance_updates = self.owner.getaddressdeltas({"addresses":[addr],"start": int(52),"end":int(100)},True)
            assert_equal( len(balance_updates), 0)

        found_txids = self.owner.getaddresstxids({"addresses":self.owner_vault_addresses},True)
        for hash in self.vault_hashes:
            assert hash in found_txids
        assert_equal(len(found_txids),len(self.vault_hashes))



if __name__ == '__main__':
    VaultUtxoIndexing ().main ()
