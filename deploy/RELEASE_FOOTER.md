
## Which file to take

| Your machine | File |
| --- | --- |
| Mac, 2020 or later | `cairn-macos-apple-silicon.tar.gz` |
| Mac, older | `cairn-macos-intel.tar.gz` |
| Linux, ordinary server or desktop | `cairn-linux-x86_64.tar.gz` |
| Linux, ARM server or Raspberry Pi | `cairn-linux-arm64.tar.gz` |
| Windows | `cairn-windows-x86_64.zip` |

Each archive holds a node, a wallet, the explorer that serves the website,
both licences, a `VERSION` file, and a `README.txt` that says what to do with
them. The names carry no version on purpose, so a link to the newest release
never has to be rewritten:

```
https://github.com/cairnchain/cairn/releases/latest/download/cairn-linux-x86_64.tar.gz
```

This release keeps its own copy of every file under its own tag, so it stays
reachable after a newer one arrives.

## Checking what you downloaded

Your operating system will warn you about these programs. It is right to:
they carry no certificate, because a certificate is something bought rather
than earned. Here is the check that is actually worth something.

```
gh attestation verify <the archive> --repo cairnchain/cairn
```

That asks GitHub which commit and which workflow produced the file, and
GitHub answers from its own records rather than from anything we control.
The build ran in the open and its log is on this repository.

`SHA256SUMS`, published beside the archives, is signed the same way. Once it
has passed the same check, it vouches for every archive it lists:

```
gh attestation verify SHA256SUMS --repo cairnchain/cairn
shasum -a 256 -c SHA256SUMS --ignore-missing
```

Comparing hashes without the first line shows only that a download arrived
whole: whoever could replace an archive could replace the list beside it.

## This is a test network

`testnet-6` money is worth nothing, is meant to be worth nothing, and the
network will be reset. Nothing on it carries over.
