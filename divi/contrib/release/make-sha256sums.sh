#!/usr/bin/env bash
# Copyright (c) 2026 The Divi developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Write the SHA256SUMS file for a directory of release archives and,
# when a key is given, PGP-clearsign it in place.
#
# The output is a single file named SHA256SUMS whose signature is inline
# (clearsigned).  That one file is what gets attached to the GitHub release,
# and it is what BasicSwap and other downloaders verify.

set -euo pipefail

usage() {
	cat <<-EOF
	Usage: $(basename -- "$0") <release-dir> [gpg-key-id]

	  release-dir   directory holding the release archives
	                (divi-*.tar.gz, divi-*.zip, divi-*.dmg, divi-*.exe)
	  gpg-key-id    the builder's key; if given, SHA256SUMS is clearsigned
	                with it, otherwise SHA256SUMS.unsigned is written and the
	                signing command is printed

	Debug archives (*-debug*) are left out on purpose.
	EOF
}

if [[ $# -lt 1 || $# -gt 2 || $1 == "-h" || $1 == "--help" ]]; then
	usage
	exit 2
fi

releasedir=$1
keyid=${2:-}

if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$@"; }
else
	sha256() { shasum -a 256 "$@"; }
fi

cd "$releasedir"

if [[ -e SHA256SUMS || -e SHA256SUMS.unsigned ]]; then
	echo "error: $releasedir already has a SHA256SUMS file, remove it first" >&2
	exit 1
fi

shopt -s nullglob
files=()
for f in divi-*.tar.gz divi-*.zip divi-*.dmg divi-*.exe; do
	[[ $f == *-debug* ]] && continue
	files+=("$f")
done
shopt -u nullglob

if [[ ${#files[@]} -eq 0 ]]; then
	echo "error: no release archives found in $releasedir" >&2
	exit 1
fi

# One line per archive: "<hash>  <file name>", sorted by name so that two
# builders hashing the same files produce byte-identical lists.
printf '%s\n' "${files[@]}" | LC_ALL=C sort | while IFS= read -r f; do
	sha256 "$f"
done > SHA256SUMS.unsigned

echo "Hashed ${#files[@]} archives:"
cat SHA256SUMS.unsigned

if [[ -z $keyid ]]; then
	echo
	echo "Not signed.  To sign, run in $releasedir:"
	echo "  gpg --digest-algo sha256 --local-user <your-key-id> --clearsign --output SHA256SUMS SHA256SUMS.unsigned && rm SHA256SUMS.unsigned"
	exit 0
fi

# The digest is forced to sha256 so the "Hash:" header gpg adds cannot be
# confused with the SHA-256 used for the files.
gpg --digest-algo sha256 --local-user "$keyid" --clearsign --output SHA256SUMS SHA256SUMS.unsigned
gpg --verify SHA256SUMS
rm SHA256SUMS.unsigned
echo
echo "Wrote signed $releasedir/SHA256SUMS.  Attach it to the GitHub release next to the archives."
