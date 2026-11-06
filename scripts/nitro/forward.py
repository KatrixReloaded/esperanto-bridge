#!/usr/bin/env python3
"""Bounded byte transport. No TLS termination, private keys, SDK processing or decryption here."""
import argparse
import concurrent.futures
import json
import selectors
import socket
import threading
import time


def relay(left, right, idle=60):
    """Copy both directions, preserving TLS bytes and TCP half-closes."""
    with left, right, selectors.DefaultSelector() as poll:
        left.setblocking(False)
        right.setblocking(False)
        poll.register(left, selectors.EVENT_READ, right)
        poll.register(right, selectors.EVENT_READ, left)
        pending = {left: bytearray(), right: bytearray()}
        reading = {left: True, right: True}
        deadline = time.monotonic() + idle
        while poll.get_map():
            if time.monotonic() >= deadline:
                raise TimeoutError("forwarding idle deadline")
            for key, events in poll.select(1):
                source, destination = key.fileobj, key.data
                if events & selectors.EVENT_READ:
                    try:
                        data = source.recv(16384)
                    except BlockingIOError:
                        data = None
                    if data:
                        pending[destination].extend(data)
                        deadline = time.monotonic() + idle
                    elif data == b"":
                        reading[source] = False
                if events & selectors.EVENT_WRITE and pending[source]:
                    try:
                        count = source.send(pending[source])
                        del pending[source][:count]
                        deadline = time.monotonic() + idle
                    except BlockingIOError:
                        pass
            for source, destination in ((left, right), (right, left)):
                # Stop reading while the receiver is slow; bound memory to <=80KiB/direction.
                mask = (selectors.EVENT_READ if reading[source] and len(pending[destination]) < 65536 else 0)
                if pending[source]:
                    mask |= selectors.EVENT_WRITE
                if not reading[destination] and not pending[source]:
                    try:
                        source.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                registered = source in poll.get_map()
                if mask and registered:
                    poll.modify(source, mask, destination)
                elif mask:
                    poll.register(source, mask, destination)
                elif registered:
                    poll.unregister(source)


def connect(address):
    if address[0] == "tcp":
        return socket.create_connection((address[1], address[2]), timeout=10)
    target = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    target.settimeout(10)
    target.connect((int(address[1]), address[2]))
    return target


def accept_loop(family, address, handler, workers=32):
    listener = socket.socket(family, socket.SOCK_STREAM)
    if family == socket.AF_INET:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(address)
    listener.listen(workers)
    slots = threading.BoundedSemaphore(workers)
    with listener, concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        while True:
            client, _ = listener.accept()
            if not slots.acquire(False):
                client.close()
                continue
            def run(client=client):
                try:
                    client.settimeout(10)
                    handler(client)
                except (OSError, ValueError):
                    client.close()
                finally:
                    slots.release()
            pool.submit(run)


def tunnel(client, allowed):
    header = bytearray()
    # Read exactly the CONNECT header; do not swallow early TLS bytes.
    while not header.endswith(b"\r\n\r\n") and len(header) < 8192:
        part = client.recv(1)
        if not part:
            raise ValueError("incomplete CONNECT")
        header.extend(part)
    request = header.decode("ascii").split("\r\n")[0].split(" ")
    if len(request) != 3 or request[0] != "CONNECT" or request[2] != "HTTP/1.1":
        raise ValueError("CONNECT required")
    hostname, port = request[1].rsplit(":", 1)
    if not ((port == "443" and hostname in allowed) or request[1] in allowed):
        client.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
        raise ValueError("outbound hostname denied")
    target = socket.create_connection((hostname, int(port)), timeout=10)
    client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    relay(client, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["tcp-vsock", "vsock-tcp", "connect-proxy"])
    parser.add_argument("--listen", type=int, required=True)
    parser.add_argument("--cid", type=int, default=3)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--target", type=int)
    parser.add_argument("--idle", type=int, default=60, help="maximum idle seconds (1 to 600)")
    parser.add_argument("--allow", help="JSON array of exact outbound HTTPS hostnames")
    args = parser.parse_args()
    if not 1 <= args.idle <= 600:
        parser.error("--idle must be between 1 and 600 seconds")
    if args.mode == "connect-proxy":
        allowed = json.loads(args.allow or "[]")
        if not allowed or not all(isinstance(h, str) and h for h in allowed):
            parser.error("provide a nonempty --allow JSON list")
        accept_loop(socket.AF_INET, (args.host, args.listen), lambda c: tunnel(c, allowed))
    else:
        if not args.target:
            parser.error("--target is required")
        target = ("vsock", args.cid, args.target) if args.mode == "tcp-vsock" else ("tcp", args.host, args.target)
        family = socket.AF_INET if args.mode == "tcp-vsock" else socket.AF_VSOCK
        address = ("127.0.0.1", args.listen) if family == socket.AF_INET else (socket.VMADDR_CID_ANY, args.listen)
        accept_loop(family, address, lambda c: relay(c, connect(target), idle=args.idle))


if __name__ == "__main__":
    main()
