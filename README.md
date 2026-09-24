# ssh_mirror.py

A reflecting SSH tarpit. For every inbound TCP connection it opens a connection
back to the connection's own source address and relays bytes in both directions.
An SSH brute-forcer pointed at the listener ends up negotiating SSH with its own
host; every credential it submits is authenticated against the attacker's own
service. If the source has nothing listening on the reflect port, the connection
falls through to an endless tarpit that dribbles a never-completing banner.

## Usage

    python3 ssh_mirror.py [options]

Direct the traffic you want to trap at `--listen-port`. The host running the
reflector must be able to reach the connection source on `--reflect-port`.

    --listen-host        bind address (default 0.0.0.0)
    --listen-port        port the reflector accepts on (default 2222)
    --reflect-port       port on the source to bounce connections back to (default 22)
    --no-tarpit-fallback close instead of tarpitting when the source has no reflect target
    --connect-timeout    seconds to wait for the reflect connection (default 5.0)
    --tarpit-delay       seconds between tarpit dribble lines (default 10.0)
    --max-conns          global ceiling on concurrently held connections (default 2000)
    --max-per-source     ceiling on concurrent connections per source IP (default 50)

Example:

    python3 ssh_mirror.py \
        --listen-port 2222 --reflect-port 22 \
        --max-conns 2000 --max-per-source 50

## How it works

1. `asyncio.start_server` accepts a connection; the source address is read from
   the socket's peer name. No log parsing is involved.
2. Admission control runs before any I/O. If the global count is at `--max-conns`,
   or this source is at `--max-per-source`, the connection is closed immediately.
   The check-and-increment is synchronous (no `await` between test and mutation),
   so it is atomic across coroutines on the single-threaded loop.
3. The reflector opens a connection to `source_ip:reflect_port`. On success it
   runs two `_pump` coroutines that copy bytes in each direction; `writer.drain()`
   applies backpressure without blocking a thread.
4. If the reflect connection fails, the connection is handed to the tarpit
   coroutine, which writes hex lines that never begin with `SSH-`, so the peer's
   version exchange never completes.

The reflector is a transparent byte relay. It does not terminate SSH, parse the
protocol, or perform any cryptography.

## Why it works

Because the relay is transparent, the SSH protocol runs end to end between the
brute-force client and the reflected-to service. Both of those endpoints are on
the source host: it acts as the SSH client (the brute-forcer) and as the SSH
server (its own sshd) for the same session. Each attempt therefore forces a
complete key exchange twice on the source machine -- once per role -- plus the
authentication path, while the reflector spends no CPU on cryptography.

Every held connection on the reflector costs one file descriptor plus a small
coroutine frame rather than a thread and stack, so the concurrency ceiling is set
by `--max-conns`, file descriptors, and connection-tracking state rather than by
thread count. Reflect mode uses two file descriptors per connection (inbound plus
the reflect connection); size `--max-conns` against `ulimit -n` accordingly.

## CPU measurements

Measured on one vCPU: a real SSH endpoint (KEX and host-key signature via
OpenSSL) standing in for the source's sshd, the reflector in front of it, and a
brute-force client issuing 200 connections through the reflector, each completing
key exchange and being rejected at authentication. CPU time was attributed per
process from `/proc/<pid>/stat`.

    role                              CPU/attempt    notes
    source sshd  (server KEX + auth)     ~1.8 ms     runs on the source host
    source client (brute-forcer)         ~2.4 ms     runs on the source host
    source total                         ~4.2 ms
    reflector    (byte relay)            ~1.2 ms     runs on the defending host

    source : reflector CPU ratio ~ 3.4 : 1

The source host spends roughly 3.4x the CPU the reflector does per attempt, and
that cost scales with the attacker's own request rate: the harder it brute-forces,
the more it drives its own two SSH endpoints. The reflector's share is userspace
byte-copying of ciphertext only; a kernel-path (DNAT) relay would reduce it
further. Absolute figures depend on negotiated algorithms, key sizes, and
hardware; the ratio is the stable quantity.

## Disclaimer

Run this only in an isolated lab against hosts you control. It originates
connections toward the source address of inbound traffic. On any network carrying
real traffic that source may be spoofed, a shared NAT gateway, or an uninvolved
third party, and originating traffic toward it -- or reflecting an attacker's
session back into a live host -- can constitute unauthorized activity regardless
of who initiated the original connection. Keep it off the open internet.
