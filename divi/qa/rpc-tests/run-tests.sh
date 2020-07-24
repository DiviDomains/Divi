#!/bin/sh

# This is a convenience script that runs all regtests that
# are supposed to work for Divi.  It is essentially a "variant" of
# qa/pull-tester/rpc-tests.sh that is not meant to be run automatically
# but just manually during development.

path=$(echo `pwd`/$0 | sed 's/\/.\//\//g' | sed 's/\/run-tests.sh//g')
set -ex

echo "$path"
cd $path
./listtransactions.py
./mempool_resurrect_test.py
./wallet.py