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

Linux, macOS, and Windows are supported, including the built-in SSH and SFTP
server.

## Command overview

Run `etcat COMMAND --help` for every option. The main workflows are:

| Goal | Server | Client |
| --- | --- | --- |
| One-shot pipe | `etcat --key=new` | `etcat TOKEN` |
| Serve TCP ports | `etcat serve 22,8080,9000-9010` | `etcat TOKEN 8080` |
| Forward listeners | `etcat serve 8080` | `etcat forward TOKEN 18080:8080` |
| Temporary SSH | `etcat serve no-auth-ssh` | `etcat ssh TOKEN` |
| Existing SSH daemon | `etcat serve 22` | `etcat ssh TOKEN` |
| Read-only files | `etcat serve files --files=DIR:ro` | `etcat ls TOKEN:.` |
| Receive files | `etcat recv DIR` | `etcat cp FILE TOKEN:` |
| SOCKS for a command | `etcat serve exit-node` | `etcat socks TOKEN curl https://example.com` |

`TOKEN` means the `etc2...` address printed by the server. A DNS name with an
`etcat=etc2...` TXT record can be used in the same places.

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

While a one-shot raw stream is active, the server processes Ctrl-C after the
peer closes that stream. Close the client side first when interrupting a hung
raw transfer.

## Expose local TCP services

The server can allow individual ports, ranges, or every local TCP port. The
root `--serve` form and the `serve` command are equivalent:

```console
server$ etcat --serve=22,8080,9000-9010
server$ etcat serve 22,8080 9000-9010
server$ etcat serve all
client$ etcat etc2... 8080
```

All destinations are connected on the server as `127.0.0.1:<port>`. EasyTier
ACLs expose only etcat's random internal gateway port; the signed application
handshake enforces the published service policy before opening a local socket.

## Local forwarding

`forward` keeps one or more local listeners open and sends each connection to
the selected server destination:

```console
server$ etcat serve 8080,9000-9010
client$ etcat forward etc2... 8080
client$ etcat forward etc2... 18080:8080 19000:9000
client$ etcat forward --bind=0.0.0.0 etc2... 0:8080
```

Mappings have these forms:

| Mapping | Meaning |
| --- | --- |
| `8080` | Listen on 8080 and connect to server port 8080 |
| `18080:8080` | Listen on 18080 and connect to server port 8080 |
| `0:8080` | Pick a free local port and print it |
| `13306:192.0.2.10:3306` | Through `exit-node`, connect to that IPv4 address |
| `13306:[2001:db8::10]:3306` | Same for IPv6 |

The default bind address is `127.0.0.1`. Exit-node mappings require the server
to run `etcat serve exit-node`.

## SSH

Start an ephemeral SSH server that accepts any user without an SSH password or
key:

```console
server$ etcat serve no-auth-ssh
client$ etcat ssh etc2...
client$ etcat ssh etc2... uname -a
```

Interactive sessions use a real PTY. The system OpenSSH client is launched with
a ProxyCommand. Its host-key database is disabled because the etcat gateway
handshake authenticates the server public key carried in the token.

`ssh` defaults to logical server port 22. `-p` accepts another server port, or
an IP/IP:port when the server has `exit-node` enabled:

```console
client$ etcat ssh -p 2222 etc2...
client$ etcat ssh -p 192.0.2.10 etc2...
client$ etcat ssh -p 192.0.2.10:2222 etc2...
```

To retain normal SSH authentication, expose the system SSH daemon instead:

```console
server$ etcat serve 22
client$ etcat ssh user@etc2...
```

The `ssh` command uses the system OpenSSH client. It preserves the child's exit
status, supports interactive PTYs and resize events, and passes `TERM`, `LANG`,
and `LC_*`. The built-in server uses one persistent SSH host key, while the
etcat gateway handshake authenticates the endpoint identified by the token.

## Files, `ls`, `cp`, and `recv`

The `files` service is rooted at one directory. Paths visible to a client
cannot escape that root, including through `..`, absolute paths, or symbolic
links.

```console
server$ etcat serve files --files=/srv/releases:ro
client$ etcat ls etc2...
client$ etcat ls -l etc2...:subdirectory
client$ etcat cp etc2...:artifact.tar.zst .
```

Available modes are:

| Mode | Access |
| --- | --- |
| `ro` | List, inspect, and download |
| `rw` | Full access inside the configured root |
| `wo` | Flat write-only drop box; uploaded names cannot overwrite files |
| `wo+` | Recursive write-only drop box; directory uploads are allowed |

`--files=DIR` defaults to `ro`. `etcat serve files` defaults to the current
directory in `ro` mode.

For receiving uploads, `recv` is the shorter and safer spelling:

```console
server$ etcat recv ./incoming
client$ etcat cp report.pdf etc2...:

server$ etcat recv --accept-dirs ./incoming
client$ etcat cp -r result-directory etc2...:
```

`cp` delegates transport behavior to the system OpenSSH `scp` client and
supports `-r`, `-p`, and `-P PORT|IP|IP:PORT`. It accepts the usual local path
and `TOKEN:PATH` operands and returns the exact `scp` exit status.

When `no-auth-ssh` is enabled without an explicit `--files`, SFTP follows the
current user's normal filesystem permissions: relative paths begin at that
user's home directory, and absolute paths retain their operating-system
meaning. Supplying `--files` always restores the rooted restriction, even when
shell access is also enabled.

On Windows, pass an absolute drive path such as `C:\\incoming` to `--files`.
Drive-relative forms such as `C:` and `C:incoming` are not accepted.

## SOCKS and process-scoped exit access

Run a command with `all_proxy` pointing at a temporary local SOCKS5 listener:

```console
server$ etcat serve 8080
client$ etcat socks curl http://etc2...:8080/
client$ etcat socks etc2... curl http://server.etcat:8080/
```

The first form puts a compact registry-relative bearer token directly in the
hostname. The fixed-token `server.etcat` form also works with longer sealed or
`--full-address` tokens; `server.tailcat` is accepted as a compatibility alias.
To reach arbitrary TCP destinations visible from the server, explicitly enable
exit-node mode:

```console
server$ etcat serve exit-node
client$ etcat socks etc2... curl https://example.com/
```

Without a child command, `socks` keeps the local proxy running. Choose the
listener with `--listen=PORT`, `--listen=IP`, or `--listen=IP:PORT`:

```console
client$ etcat socks --listen=127.0.0.1:1080 etc2...
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

`ping` performs an authenticated application handshake and reports whether
EasyTier currently uses a direct peer path or the shared relay. A DNS name is
accepted anywhere a token is accepted when its TXT records contain:

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
server$ etcat genkey --key=default
server$ etcat genkey --key=home --fixed-relay
server$ etcat genkey --key=office --relay=community-1
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
client$ etcat genkey --client --key=client-default
# prints the public key and saves client-default

server$ etcat --serve=22 --allow='<client public key>'
```

Multiple `--allow` values are supported. Each recipient gets a distinct
EasyTier credential sealed with HPKE. Clients automatically use
`client-default`, or a named identity selected with `--key`. Key files and
`ETCAT_ADDR_FILE` token files are written with mode `0600` on Unix.
`--allow=none` starts a server that issues no usable client credential.

Key generation and deletion deliberately require an explicit `--key`; there is
no implicit file creation. `etcat printpub` prints `client-default` when it
exists and otherwise prints a temporary public key. Use
`etcat --key=new printpub` to force a temporary key.

`--ttl=30m` adds an absolute credential expiry. Without `--ttl`, an ephemeral
token is process-bound because its credential exists only in the running
server. A saved server key intentionally produces a reusable token across
server restarts.

## Shared relay registry

The built-in list lives in [`relays.toml`](relays.toml). It currently contains a
best-effort community relay that has passed an end-to-end etcat transfer test,
including through its browser-compatible WSS endpoint. It has no uptime
guarantee or independently published EasyTier public key. TLS authenticates the
WSS hostname, but EasyTier will still warn that the relay identity is not
pinned. Override the registry with `--relay-file` or `ETCAT_RELAY_FILE`:

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

## Rust library

The package also exposes the transport as a Rust library. `Client` keeps one
EasyTier session alive for repeated dials; `Server` accepts authenticated
streams and reports the requested logical destination:

```rust,no_run
use etcat::{Client, ClientOptions, ConnectionToken, Destination, Server,
    ServerOptions};

# async fn example(encoded: &str) -> anyhow::Result<()> {
let token = ConnectionToken::decode(encoded)?;
let client = Client::connect(token, &ClientOptions::default()).await?;
let stream = client.dial_port(8080).await?;

let server = Server::bind(&ServerOptions::default()).await?;
println!("{}", server.token().encode()?);
let incoming = server.accept().await?;
if let Destination::ServerPort { port } = incoming.destination {
    println!("client requested port {port}");
}
# drop(stream);
# Ok(())
# }
```

The public file-service types are `FileService`, `FileMode`, and `FileSession`.
Use them when embedding the rooted SFTP policy in another SSH server.

## Tailcat workflow coverage

The native CLI covers Tailcat's pipe, `serve`, `ping`, `socks`, `ssh`, `cp`,
`ls`, `forward`, `recv`, `parse`, `resolve`, `genkey`, `printpub`, `version`, and
`readme` workflows. etcat has its own `etc2` token and EasyTier relay protocol;
it does not read Tailcat tokens.

## Browser send and receive

The EasyTier WebAssembly runtime also provides an etcat browser page and
TypeScript client/server API under
[`easytier-cloudflare-worker/browser`](https://github.com/EasyTier/EasyTier/tree/main/easytier-contrib/easytier-cloudflare-worker/browser).
It implements Tailcat's browser send/receive workflow: create a receiver token,
send text or a file to logical port 1, half-close the stream, and wait for the
receiver to confirm EOF. Browser-created bearer tokens work with the native
CLI:

```console
browser$ Create listener, then copy etc2...
client$ etcat etc2... < archive.tar.zst
```

Browser networking is relay-only. Its relay must publish a `ws://` or
`wss://` EasyTier endpoint, and an HTTPS page can use only `wss://`. To send
from the browser to a native receiver, use a relay registry containing such an
endpoint and print a self-contained token:

```console
server$ etcat --relay-file=relays.toml --full-address --key=new
browser$ Paste the printed token under Send
```

The checked-in community relay includes a publicly trusted WSS endpoint, so the
browser works with `community-1` without extra relay configuration. Browser
listeners use ephemeral keys unless the user explicitly enables browser-local
persistence. Sealed `--allow`/HPKE client tokens are not supported by the
browser API yet; bearer tokens are supported.

## License

The original etcat source is licensed under Apache License 2.0; see
[`LICENSE`](LICENSE). EasyTier is an LGPL-3.0 dependency. Distributors of
compiled binaries must also satisfy EasyTier's license and the licenses of all
other linked dependencies.
