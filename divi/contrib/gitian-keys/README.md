Builder keys
============

This folder holds the public PGP keys of the people who build and sign Divi
releases.  A key in this folder means: "a `SHA256SUMS` file signed by this key
is a genuine Divi release".  `contrib/release/verify-release.sh` trusts these
keys and no others.

The folder is empty until the first builder adds their key.  Until then,
`verify-release.sh` stops with "no builder keys", on purpose.

The five keys that used to sit here came in with the 2018 copy of PIVX 3.0.6.
They belong to PIVX developers, two of them have expired, and none of them
ever signed a Divi release, so they were removed.

Adding your key
---------------

1. Use a long-lived signing key that you control and keep offline when you
   can.  Export the public half only:

       gpg --armor --export <your-key-fingerprint> > contrib/gitian-keys/<your-name>.asc

2. Open a pull request that adds `<your-name>.asc`.  In the description, give
   the full 40-character fingerprint and say where else you have published it
   (for example your GitHub profile or keys.openpgp.org) so others can cross-check.

3. Once merged, also submit the same key to BasicSwap
   (`basicswap/pgp/keys/divi_<your-name>.pgp`) so it can check Divi releases.

Removing a key
--------------

If a builder stops building, or a key is lost or compromised, remove the file
in a pull request that says why.  A compromised key must also be revoked and
the revocation published.

See [doc/release-signing.md](../../doc/release-signing.md) for the full
release and signing process.
