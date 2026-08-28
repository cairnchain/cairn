
## Which file to take

| Your machine | File |
| --- | --- |
| Mac, 2020 or later | `macos-apple-silicon.tar.gz` |
| Mac, older | `macos-intel.tar.gz` |
| Linux, ordinary server or desktop | `linux-x86_64.tar.gz` |
| Linux, ARM server or Raspberry Pi | `linux-arm64.tar.gz` |
| Windows | `windows-x86_64.zip` |

Each archive holds a node, a wallet, both licences, and a `README.txt` that
says what to do with them.

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

Or compare hashes against `SHA256SUMS`, published beside the archives:

```
shasum -a 256 <the archive>
```

## This is a test network

`testnet-2` money is worth nothing, is meant to be worth nothing, and the
network will be reset. Nothing on it carries over.
