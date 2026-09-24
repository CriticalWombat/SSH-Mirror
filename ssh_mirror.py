#!/usr/bin/env python3
"""
ssh_mirror.py -- LAB-ONLY SSH "boomerang" tarpit.

Two bounds keep the trap from DoS-ing your own host under a flood:
  --max-conns        global ceiling on concurrently held connections
  --max-per-source   ceiling per source IP (one attacker can't eat the budget)
When either cap is hit, new connections are refused immediately (closed), not
held.

DO NOT run this against real internet traffic. See README.
"""
import argparse, asyncio, contextlib, logging

log = logging.getLogger("boomerang")


async def _safe_close(writer):
    with contextlib.suppress(OSError, asyncio.CancelledError):
        writer.close()
        await writer.wait_closed()


async def _pump(reader, writer):
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            writer.write(data)
            await writer.drain()          # backpressure, no thread blocked
    except (OSError, asyncio.CancelledError):
        pass


async def relay(cr, cw, ur, uw):
    t1 = asyncio.create_task(_pump(cr, uw))
    t2 = asyncio.create_task(_pump(ur, cw))
    try:
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for t in (t1, t2):
            if not t.done():
                t.cancel()
        for t in (t1, t2):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t
        await _safe_close(cw)
        await _safe_close(uw)


async def tarpit(writer, ip, delay):
    log.info("tarpit  %s (no reflect target, dribbling forever)", ip)
    i = 0
    try:
        while True:
            writer.write(b"%08x\r\n" % (i & 0xffffffff))
            await writer.drain()
            i += 1
            await asyncio.sleep(delay)
    except (OSError, asyncio.CancelledError):
        pass
    finally:
        await _safe_close(writer)


class Reflector:
    def __init__(self, args):
        self.reflect_port = args.reflect_port
        self.fallback = not args.no_tarpit_fallback
        self.timeout = args.connect_timeout
        self.delay = args.tarpit_delay
        self.max_total = args.max_conns
        self.max_per_source = args.max_per_source
        self.total = 0
        self.per_source = {}

    # admission + release run with no 'await' between check and mutation,
    # so they are atomic w.r.t. other coroutines on the single-thread loop.
    def _admit(self, ip):
        if self.total >= self.max_total:
            return "global-cap"
        if self.per_source.get(ip, 0) >= self.max_per_source:
            return "per-source-cap"
        self.total += 1
        self.per_source[ip] = self.per_source.get(ip, 0) + 1
        return None

    def _release(self, ip):
        self.total -= 1
        n = self.per_source.get(ip, 0) - 1
        if n <= 0:
            self.per_source.pop(ip, None)
        else:
            self.per_source[ip] = n

    async def handle(self, creader, cwriter):
        peer = cwriter.get_extra_info("peername")
        ip = peer[0] if peer else "?"
        reason = self._admit(ip)
        if reason:
            log.info("refuse  %s (%s, total=%d)", ip, reason, self.total)
            await _safe_close(cwriter)
            return
        log.info("inbound %s (total=%d, from_this_ip=%d)",
                 ip, self.total, self.per_source[ip])
        try:
            await self._serve(ip, creader, cwriter)
        finally:
            self._release(ip)
            log.info("closed  %s (total=%d)", ip, self.total)

    async def _serve(self, ip, creader, cwriter):
        try:
            ureader, uwriter = await asyncio.wait_for(
                asyncio.open_connection(ip, self.reflect_port),
                timeout=self.timeout)
        except (OSError, asyncio.TimeoutError) as e:
            log.info("reflect %s:%s failed: %s", ip, self.reflect_port, e)
            if self.fallback:
                await tarpit(cwriter, ip, self.delay)
            else:
                await _safe_close(cwriter)
            return
        log.info("reflect %s -> %s:%s (they are now talking to themselves)",
                 ip, ip, self.reflect_port)
        await relay(creader, cwriter, ureader, uwriter)


async def main_async(args):
    r = Reflector(args)
    server = await asyncio.start_server(
        r.handle, args.listen_host, args.listen_port)
    log.info("listening %s:%s  reflect->source:%s  max_conns=%d  max_per_source=%d",
             args.listen_host, args.listen_port, args.reflect_port,
             args.max_conns, args.max_per_source)
    async with server:
        await server.serve_forever()


def main():
    ap = argparse.ArgumentParser(description="Lab-only async SSH boomerang / reflector")
    ap.add_argument("--listen-host", default="0.0.0.0")
    ap.add_argument("--listen-port", type=int, default=2222)
    ap.add_argument("--reflect-port", type=int, default=22)
    ap.add_argument("--no-tarpit-fallback", action="store_true")
    ap.add_argument("--connect-timeout", type=float, default=5.0)
    ap.add_argument("--tarpit-delay", type=float, default=10.0)
    ap.add_argument("--max-conns", type=int, default=2000,
                    help="global ceiling on concurrently held connections")
    ap.add_argument("--max-per-source", type=int, default=50,
                    help="ceiling on concurrent connections per source IP")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
