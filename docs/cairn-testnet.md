---
title: Join testnet-8
language: en
stylesheet: cairn-whitepaper.css
strap:
  How to run a node on Cairn's public test network, make a wallet from
  twenty four words, get test coins and pay someone, on Linux, macOS or
  Windows.
byline: For release 0.14.0, 29 October 2026
byline: [github.com/cairnchain/cairn](https://github.com/cairnchain/cairn)
byline: Every command below was run against that release and the live network
abstract: What this is
---

# Join testnet-8

`testnet-8` is Cairn's public test network. It opened on 5 October 2026 at
18:00 UTC. Its coins are worthless, are meant to stay worthless, and the
network will be reset; nothing on it carries over to anything else. It is
here to be run, attacked and criticised.

Cairn was written, and audited, by an AI model, and no human has reviewed it
yet. [The guide for reviewers](https://cairnchain.org/for-reviewers) says
where the claims are and what has already gone wrong.

## What you need

A computer running Linux, macOS or Windows, a few hundred megabytes of disk,
and a connection that reaches the internet. No account and no key from us.
Each command below is written for a terminal opened in the folder the
archive unpacks to; on Windows, in PowerShell, write `.\cairnd.exe` where
this page writes `./cairnd`, and the same for the other two programs.

## Get the programs

Download the archive for your system from the
[release page](https://github.com/cairnchain/cairn/releases/tag/v0.14.0),
with the `SHA256SUMS` file beside it, and unpack it:

```
tar -xzf cairn-linux-x86_64.tar.gz
cd cairn-0.14.0-linux-x86_64
```

The other archives are `cairn-linux-arm64.tar.gz`,
`cairn-macos-apple-silicon.tar.gz`, `cairn-macos-intel.tar.gz` and
`cairn-windows-x86_64.zip`, which PowerShell unpacks with
`Expand-Archive cairn-windows-x86_64.zip -DestinationPath .`. Each holds the
same three programs: `cairnd`, the node, `cairn-wallet` and `cairn-explorer`.

Your system will warn you that the programs are not signed with a paid
certificate. On macOS, once you have checked them, tell it where they came
from:

```
xattr -d com.apple.quarantine cairnd cairn-wallet cairn-explorer
```

There are three checks, and they prove different things. The first only
shows that the download arrived whole, against the list published beside it:

```
shasum -a 256 -c SHA256SUMS --ignore-missing
```

On Windows, `certutil -hashfile cairn-windows-x86_64.zip SHA256` prints the
hash to compare with its line in `SHA256SUMS`.

The second asks GitHub which commit and which workflow built the archive.
It needs the GitHub command line, `gh`, signed in to a GitHub account of
your own:

```
gh attestation verify cairn-macos-apple-silicon.tar.gz --repo cairnchain/cairn
```

The third needs nobody's word, GitHub's included, and is described at the
end of this page: build the Linux archive again from its tag and compare the
bytes.

## Run a node

```
./cairnd
```

That is the whole command. The addresses it starts from are written into the
program, as the network's first block is. Within a minute it prints a status
line with a height close to the explorer's at https://cairnchain.org and a
few peers. It does not download the whole history: a newcomer is handed a
ledger by a peer, after weighing a sample of the headers, and checks the
blocks above it itself. For a while it also says it cannot yet show the chain
to somebody arriving new, while it collects the older headers; that is
expected, and it carries on. Its chain is in the folder `cairn-data`. Stop it
with Ctrl-C.

## Make a wallet from twenty four words

```
./cairn-wallet new me.key
```

It shows twenty four words once, asks for three of them back, then writes
the key file and prints the address you are paid at, which
`./cairn-wallet address me.key` prints again at any time. Write the words on
paper. They make the same key again on any machine:

```
./cairn-wallet restore me.key
```

`restore` reads the words from its input, never from its command line, and
refuses to write over a file that is there. On a test network none of this
matters; the habit does.

## Get test coins

There is no faucet. There are two ways.

**Mine them.** Stop the node, and start it again mining to your address:

```
./cairnd --mine <the address new printed>
```

It waits until it has a peer, then mines, and prints a line for each block
it finds. A block pays 50 CAIRN, which can be spent 1 024 blocks after it,
about seventeen hours at a block a minute: the rules hold a reward still
until nothing can undo the block that paid it. The difficulty follows the
whole network's hash rate, so what one computer finds depends on how many
others are mining. On 29 October 2026 one laptop found two blocks in its
first seven minutes, which was luck as much as speed.

**Ask.** Open an issue on [GitHub](https://github.com/cairnchain/cairn/issues)
with your address, or ask in the discussion thread, and the project sends
some from its miner's rewards. That is done by hand, so it takes hours
rather than minutes.

## See your balance and pay someone

```
./cairn-wallet balance me.key
```

The wallet is a node of its own: it joins the network, checks the chain, and
only then answers, with its copy of the chain in `cairn-wallet-data`. It runs
beside a node on the same machine without trouble. A reward not yet
spendable is shown apart, with the block it moves at.

```
./cairn-wallet open me.key
```

prints an address to open in your browser: the balance, the address to be
paid at, and a form to pay from. The address carries a secret drawn for that
run; without it the page answers nothing. From the command line instead:

```
./cairn-wallet send me.key --to <their address> --amount 1
```

It says who is paid, how much, the fee and the total, and asks before
sending. Only a block confirms a payment, and `balance` lists it as waiting
until then. No payment between two people has been made on testnet-8 yet,
so the first ones are worth a line in the discussion thread.

A wallet is its key file and the `history.dat` and `pending.dat` its data
folder keeps beside the chain, and `./cairn-wallet backup me.key --into
<folder>` copies all of them.

## Watch the network

The public explorer is https://cairnchain.org. To run your own:

```
./cairn-explorer
```

It prints the address of its site, `http://127.0.0.1:8080/`. An explorer
keeps every block and reads the chain from the first one, so on testnet-8
today it takes most of an hour before its pages reach the tip.

## Rebuild a Linux release yourself

The attestation is GitHub saying which commit built each archive. This is
the check that does not need GitHub to tell the truth. From a clone of the
repository, with git, curl and Docker installed:

```
deploy/rebuild.sh 0.14.0
```

It checks out the tag, builds the Linux archive for your processor in the
container the release was built in, named by its digest, and says whether
the result is the published file, byte for byte. `all` as a second argument
builds both Linux archives. macOS and Windows archives cannot yet be rebuilt
identically on another machine; `deploy/README.md` says why. Every release
is built twice on GitHub and the two compared before it is published.

## What we would like you to try

- Leave a node running for days, stop it, come back a week later and see
  whether it catches up on its own.
- Join from behind a slow or unreliable connection.
- Mine in bursts: start and stop a powerful machine.
- Make the first payments on the network, and spend a note old enough to
  have fallen out of the hot set.
- Read the [threat model](https://cairnchain.org/threat-model) and try what
  it says should fail, against nodes of your own. Do not flood the hosted
  servers: a flood tells us nothing a local test does not, and stops other
  people's tests. `--network devnet` runs the same rules on one machine with
  a five second block.

## Reporting

Anything that surprises you is worth an issue on
[GitHub](https://github.com/cairnchain/cairn/issues): what you ran, what you
expected, what the program printed. A security problem goes by the route in
[SECURITY.md](https://github.com/cairnchain/cairn/blob/main/SECURITY.md)
instead.
