# etcat

`etcat` is a netcat-like, rootless peer-to-peer tool built on
[EasyTier](https://github.com/EasyTier/EasyTier). One process prints a
connection token; another process uses that token to pipe data, reach selected
local TCP services, open an SSH session, or use the server as a process-scoped
SOCKS exit.

It is deliberately **not a VPN**. Both peers run EasyTier with `no_tun` and a
userspace TCP/IP stack. `etcat` does not create a TUN device, alter routes or
DNS, bind privileged ports, or require root/administrator privileges.

> This project is experimental. Tokens and the CLI may change before 1.0.

## Install

Linux and macOS:

```console
curl --proto '=https' --tlsv1.2 -LsSf https://raw.githubusercontent.com/EasyTier/etcat/main/install.sh | sh
```

The Unix installer selects the native platform archive and installs `etcat` to
`/usr/local/bin`, using `sudo` only when the directory is not writable. Linux
downloads are statically linked musl binaries.

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/EasyTier/etcat/main/install.ps1 | iex
```

The Windows installer writes to `%LOCALAPPDATA%\Programs\etcat` and adds that
directory to the user `PATH`. Both installers verify the release archive against
the published `SHA256SUMS`. Set `ETCAT_VERSION` to install a specific release,
or `ETCAT_INSTALL_DIR` to choose another destination:

```console
curl --proto '=https' --tlsv1.2 -LsSf https://raw.githubusercontent.com/EasyTier/etcat/main/install.sh | ETCAT_VERSION=v0.1.0 ETCAT_INSTALL_DIR="$HOME/.local/bin" sh
```

```powershell
$env:ETCAT_VERSION = "v0.1.0"
$env:ETCAT_INSTALL_DIR = "C:\Tools\etcat"
irm https://raw.githubusercontent.com/EasyTier/etcat/main/install.ps1 | iex
```

Release archives are also available from the
[GitHub releases page](https://github.com/EasyTier/etcat/releases) for Linux
x86-64/ARM64, macOS Intel/Apple Silicon, and Windows x64/ARM64.

## Build

Rust 1.95 or newer is required. EasyTier is pinned to commit
`164e2db6aecd13117d840821d5b889b51cb7c463`.

```console
cargo build --release
./target/release/etcat --help
./target/release/etcat --readme
```

Linux, macOS, and Windows are supported. The built-in no-auth SSH server is
available on Unix; forwarding to an existing SSH server works everywhere.

## Pipe stdin to another machine

Start an ephemeral server. The token is printed to stderr and becomes useless
when this process exits:

```console
server$ etcat --key=new
# Server listening with address: etc2...
```

Send data from the client:

```console
client$ printf 'hello\n' | etcat etc2...
```

The server writes `hello` to stdout and exits.

## Expose local TCP services

The server can allow individual ports, ranges, or every local TCP port:

```console
server$ etcat --serve=22,8080,9000-9010
server$ etcat --serve=all
client$ etcat etc2... 8080
```

All destinations are connected on the server as `127.0.0.1:<port>`. EasyTier
ACLs expose only etcat's random internal gateway port; the signed application
handshake enforces the published service policy before opening a local socket.

## SSH

On Linux and macOS, start an ephemeral SSH server that accepts any user without
an SSH password or key:

```console
server$ etcat --serve=no-auth-ssh
client$ etcat ssh etc2...
client$ etcat ssh etc2... uname -a
```

Interactive sessions use a real PTY. The system OpenSSH client is launched with
a ProxyCommand. Its host-key database is disabled because the etcat gateway
handshake authenticates the server public key carried in the token.

To retain normal SSH authentication, expose the system SSH daemon instead:

```console
server$ etcat --serve=22
client$ etcat ssh -p 22 etc2...
```

## SOCKS and process-scoped exit access

Run a command with `all_proxy` pointing at a temporary local SOCKS5 listener:

```console
server$ etcat --serve=8080
client$ etcat socks curl http://etc2...:8080/
client$ etcat socks etc2... curl http://server.etcat:8080/
```

The first form puts a compact registry-relative bearer token directly in the
hostname. The fixed-token `server.etcat` form also works with longer sealed or
`--full-address` tokens; `server.tailcat` is accepted as a compatibility alias.
To reach arbitrary TCP destinations visible from the server, explicitly enable
exit-node mode:

```console
server$ etcat --serve=exit-node
client$ etcat socks etc2... curl https://example.com/
```

This affects only the child command or the explicitly printed local SOCKS
listener. It never installs a default route and never becomes a system VPN.
Only SOCKS5 TCP `CONNECT` is supported.

## Connectivity, tokens, and DNS

```console
etcat ping etc2...
etcat ping --until-direct --timeout=20s etc2...
etcat parse etc2...
etcat resolve etc2...
etcat relays
```

`ping` reports whether EasyTier currently uses a direct peer path or the shared
relay. A DNS name is accepted anywhere a token is accepted when its TXT records
contain:

```text
etcat=etc2...
```

`--full-address` embeds the selected relay metadata. Otherwise the token stores
a permanent built-in relay number or the custom relay ID, and clients resolve
it through their local `relays.toml`. `etc2` tokens use a fixed binary
layout and lowercase Base32 hostname labels. A normal bearer token using the
built-in relay is 65 characters. It carries a 128-bit credential seed and a
128-bit fingerprint of the server signing key; the gateway returns the full
public key and proves possession during its signed handshake.

## Key management and client authorization

The safe server default is a new in-memory identity and credential. Create a
persistent server identity only when a stable token is required:

```console
server$ etcat genkey
server$ etcat genkey --fixed-relay
server$ etcat genkey --relay=official-global
server$ etcat genkey --list
server$ etcat genkey --delete --key=default
```

Once the `default` server key exists, it is used automatically. `--key=new`
always forces an ephemeral server. `--fixed-relay` measures latency once and
stores the winner; an explicit `--relay` is also fixed. Without either option,
a saved server identity selects the nearest relay at every start.

Bearer tokens authorize one logical client identity by default. For a token
that only named clients can open, generate a client key and give its public key
to the server:

```console
client$ etcat genkey --client
# prints the public key and saves client-default

server$ etcat --serve=22 --allow='<client public key>'
```

Multiple `--allow` values are supported. Each recipient gets a distinct
EasyTier credential sealed with HPKE. Clients automatically use
`client-default`, or a named identity selected with `--key`. Key files and
`ETCAT_ADDR_FILE` token files are written with mode `0600` on Unix.
`--allow=none` starts a server that issues no usable client credential.

`--ttl=30m` adds an absolute credential expiry. Without `--ttl`, an ephemeral
token is process-bound because its credential exists only in the running
server. A saved server key intentionally produces a reusable token across
server restarts.

## Shared relay registry

The built-in list lives in [`relays.toml`](relays.toml). It currently contains a
best-effort community relay that has passed an end-to-end etcat transfer test,
but has no uptime guarantee or independently published public key. Override the
registry with `--relay-file` or `ETCAT_RELAY_FILE`:

```toml
version = 1

[[relay]]
id = "my-relay"
region = "Office"
probe = "relay.example.com:11010"
priority = 10
endpoints = [
  "tcp://relay.example.com:11010",
  "udp://relay.example.com:11010",
]
public_key = "base64-encoded-32-byte-EasyTier-public-key"
```

Relay candidates are probed concurrently with three TCP samples and tried in
median-RTT order. Startup fails only after every reachable candidate fails its
EasyTier handshake. etcat prints the server token only after a connection to the
selected relay is established. When `public_key` is present, EasyTier must
authenticate that exact relay key. When it is absent, the relay is encrypted but
unpinned and etcat prints a warning.

## Security model

- Treat a bearer `etc2...` token like a password. Avoid shell
  history, public logs, issue trackers, and process arguments on shared
  machines. Prefer `--allow` when a token will be published in DNS or retained
  long term.
- EasyTier secure mode encrypts the overlay and admits clients with managed
  credentials. Credential clients cannot advertise proxy routes, and client
  ACLs reject gateway traffic routed to another credential peer. An independent
  Ed25519-signed gateway handshake pins the exact server identity carried in the
  token and authorizes each logical destination. Requests also carry an HMAC
  whose key is derived separately from the same token credential, preventing
  local processes from bypassing the overlay through etcat's loopback gateway.
- Shared relays provide rendezvous and fallback transport. A pinned relay key
  authenticates the relay; an unpinned registry entry does not.
- `--serve=all`, `--serve=exit-node`, and `--serve=no-auth-ssh` grant broad
  capabilities to anyone who can open the token. Use them intentionally.
- No-availability guarantee is implied for community shared relays. A private,
  pinned EasyTier relay is recommended for durable use.

## Tailcat CLI compatibility

Tailcat's user-facing workflows work with `tailcat` replaced by `etcat`,
including pipe, served ports, ping, SOCKS, SSH, parse, resolve, key management,
`--readme`, `--allow=none`, and the common genkey flag aliases. EasyTier-specific
relay configuration remains `--relay-file`, `--relay`, and `--fixed-relay`.
The native names are `etc2...`, `server.etcat`, `ETCAT_ADDR_FILE`, and
`etcat=etc2...` DNS TXT records; the corresponding Tailcat environment,
hostname, and TXT labels are accepted as compatibility aliases where they are
unambiguous.

## License

The original etcat source is licensed under Apache License 2.0; see
[`LICENSE`](LICENSE). EasyTier is an LGPL-3.0 dependency. Distributors of
compiled binaries must also satisfy EasyTier's license and the licenses of all
other linked dependencies.
