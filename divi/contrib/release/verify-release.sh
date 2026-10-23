#!/usr/bin/env bash
# Copyright (c) 2026 The Divi developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check downloaded release archives against a signed SHA256SUMS file.
#
# The signature must come from one of the builder keys in
# contrib/gitian-keys/ (or the directory given with --keys).  Only the signed
# part of SHA256SUMS is trusted; anything outside the signature is ignored.
# Exits 0 only if the signature is good and every archive present in the
# directory matches its signed hash.

set -euo pipefail

usage() {
	cat <<-EOF
	Usage: $(basename -- "$0") [--keys <dir>] <release-dir>

	  release-dir   directory holding SHA256SUMS and the downloaded archives
	  --keys <dir>  directory of trusted builder public keys (*.asc);
	                default: contrib/gitian-keys next to this script
	EOF
}

keysdir="$(cd "$(dirname -- "$0")/../gitian-keys" && pwd)"
if [[ ${1:-} == "--keys" ]]; then
	[[ $# -ge 2 ]] || { usage; exit 2; }
	keysdir=$2
	shift 2
fi

if [[ $# -ne 1 || $1 == "-h" || $1 == "--help" ]]; then
	usage
	exit 2
fi

releasedir=$1

if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$@"; }
else
	sha256() { shasum -a 256 "$@"; }
fi

shopt -s nullglob
keys=("$keysdir"/*.asc)
shopt -u nullglob
if [[ ${#keys[@]} -eq 0 ]]; then
	echo "error: no builder keys (*.asc) in $keysdir" >&2
	exit 1
fi

if [[ ! -f $releasedir/SHA256SUMS ]]; then
	echo "error: $releasedir/SHA256SUMS not found" >&2
	exit 1
fi

# A throwaway keyring holding only the trusted builder keys, so a key that
# happens to be in the user's own keyring can never satisfy the check.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export GNUPGHOME=$tmp/gnupg
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --import "${keys[@]}" 2>/dev/null

if ! gpg --batch --status-file "$tmp/status" --output "$tmp/signed-body" \
		--decrypt "$releasedir/SHA256SUMS" 2>"$tmp/gpg.log"; then
	cat "$tmp/gpg.log" >&2
	echo "FAIL: SHA256SUMS is not signed by a trusted builder key" >&2
	exit 1
fi
signer=$(awk '$2 == "VALIDSIG" { print $3 }' "$tmp/status")
if [[ -z $signer ]]; then
	echo "FAIL: no valid signature found on SHA256SUMS" >&2
	exit 1
fi
echo "Good signature on SHA256SUMS from key $signer"

checked=0
failed=0
while read -r hash name; do
	[[ -z $hash ]] && continue
	if [[ ! -f $releasedir/$name ]]; then
		continue
	fi
	actual=$(cd "$releasedir" && sha256 "$name" | awk '{ print $1 }')
	if [[ $actual == "$hash" ]]; then
		echo "OK    $name"
	else
		echo "FAIL  $name" >&2
		failed=$((failed + 1))
	fi
	checked=$((checked + 1))
done < "$tmp/signed-body"

if [[ $checked -eq 0 ]]; then
	echo "FAIL: none of the files listed in SHA256SUMS are in $releasedir" >&2
	exit 1
fi
if [[ $failed -ne 0 ]]; then
	echo "FAIL: $failed of $checked archives do not match SHA256SUMS" >&2
	exit 1
fi
echo "All $checked archives match the signed SHA256SUMS."
