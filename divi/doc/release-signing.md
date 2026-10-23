Release signing
===============

Every Divi release ships a `SHA256SUMS` file that a release builder has signed
with PGP.  Anyone who downloads a release can check that:

1. the signature on `SHA256SUMS` comes from a builder key listed in
   [`contrib/gitian-keys/`](../contrib/gitian-keys/README.md), and
2. each downloaded archive has the hash listed inside the signed part of
   `SHA256SUMS`.

Exchanges, wallets and other programs that download Divi can check a
release this way before they run it.

What a release contains
-----------------------

A release lives at `https://github.com/DiviProject/Divi/releases/tag/v<version>`
and has these files attached:

| File | What it is |
|---|---|
| `divi-<version>-x86_64-linux-gnu-<commit>.tar.gz` | Linux, 64-bit Intel/AMD |
| `divi-<version>-RPi2-<commit>.tar.gz` | Raspberry Pi |
| `divi-<version>-osx64-<commit>.tar.gz` | macOS |
| `divi-<version>-win64-<commit>.zip` | Windows |
| `SHA256SUMS` | the list of hashes above, clearsigned by a builder |

`<commit>` is the first seven characters of the release commit, added by
`DeploymentScripts/continuous_build.sh`.  `SHA256SUMS` is always named exactly
that, with no version in the name, so a downloader can build its URL from the
version alone:

    https://github.com/DiviProject/Divi/releases/download/v<version>/SHA256SUMS

The signature is inline (clearsigned), so there is one file to download, not
a separate `.asc`.  Debug archives (`*-debug*`) are not listed and should not
be uploaded.

Making a release (builder)
--------------------------

1. Tag the release commit `v<version>` and build it.  The reproducible way is
   gitian, see [release-process.md](release-process.md); the archives can also
   come from the deployment scripts.
2. Put the release archives, and nothing else, in one folder.
3. Hash and sign them:

       contrib/release/make-sha256sums.sh <folder> <your-key-fingerprint>

   This writes `<folder>/SHA256SUMS`, checks the signature, and refuses to
   overwrite an existing `SHA256SUMS`.  Without a key it writes
   `SHA256SUMS.unsigned` and prints the command to sign it on another machine.
4. Check the result exactly the way a user would:

       contrib/release/verify-release.sh <folder>

5. Create the GitHub release for the tag and attach the archives and
   `SHA256SUMS`.

Only sign archives you built yourself, or whose hashes you reproduced with
your own gitian build.  A signature says "I vouch for these exact bytes".

Checking a release (anyone)
---------------------------

Download the archives you want and `SHA256SUMS` into one folder, then run:

    contrib/release/verify-release.sh <folder>

It imports only the keys in `contrib/gitian-keys/` into a temporary keyring,
so keys you happen to have in your own keyring cannot make a bad release
pass.  It reads hashes only from the signed part of the file, ignores files
you did not download, and exits with an error if the signature is missing,
made by an unknown key, or if any downloaded archive does not match.

To check by hand instead (on macOS use `shasum -a 256` for `sha256sum`):

    gpg --import contrib/gitian-keys/*.asc
    gpg --verify SHA256SUMS
    gpg --decrypt SHA256SUMS 2>/dev/null | sha256sum --ignore-missing -c -

The last line checks the hashes from the signed part only.

Becoming a builder
------------------

See [contrib/gitian-keys/README.md](../contrib/gitian-keys/README.md): add your
public key there in a pull request.  Programs that check Divi releases
keep their own copy of the builder keys, so tell their maintainers when a
key is added or removed.

Stronger: more than one builder
-------------------------------

One signed `SHA256SUMS` proves who published a release.  It does not prove
the binaries match the source code.  Reproducible gitian builds do: when two
or more builders build the same tag and get the same hashes, nobody has to
trust any single builder.  The path there:

- At least two builders with keys in `contrib/gitian-keys/`.
- A public `gitian.sigs` repository where each builder commits the signed
  build results (`gitian-build.sh` already does this with `gsign`).  That
  repository does not exist yet; `gitian-build.sh --setup` still clones the
  old `divicoin/gitian.sigs` until it does.
- Each builder signs `SHA256SUMS` only after the gitian results match.

Code signing for macOS and Windows (`divi-detached-sigs`, the `*-signer.yml`
descriptors) is a separate step that needs Apple and Windows certificates.
It is not needed to check a release with `SHA256SUMS` and is not set up.
