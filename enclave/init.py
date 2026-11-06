#!/usr/bin/env python3
"""All secret-processing services run inside this one EIF. Supervise and fail closed."""
import json
import os
import signal
import socket
import subprocess
import time

children = []


def stop(*_):
    for child in children:
        child.terminate()
    for child in children:
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
    raise SystemExit(1)


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)
try:
    subprocess.run(["/usr/sbin/ip", "link", "set", "lo", "up"], check=True)
    for args in [
        ["vsock-tcp", "--listen", "8443", "--target", "8443"],
        ["tcp-vsock", "--listen", "8444", "--cid", "3", "--target", "8444"],
        ["tcp-vsock", "--listen", "8445", "--cid", "3", "--target", "8445"],
        ["tcp-vsock", "--listen", "8888", "--cid", "3", "--target", "8888"],
    ]:
        children.append(subprocess.Popen(["/usr/bin/python3", "/app/forward.py", *args]))
    config = json.load(open("/etc/cwxmr/sidecar.json"))
    rpc = config["ethereum_rpc"]
    if not isinstance(rpc, str) or not rpc.startswith("https://"):
        raise ValueError("SDK RPC requires enclave-terminated HTTPS")
    sdk_env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin", "SIDECAR_PORT": "8788", "SEPOLIA_RPC_URL": rpc,
        "NODE_USE_ENV_PROXY": "1", "HTTP_PROXY": "http://127.0.0.1:8888",
        "HTTPS_PROXY": "http://127.0.0.1:8888", "NO_PROXY": "localhost,127.0.0.1",
    }
    children.append(subprocess.Popen(["/usr/local/bin/node", "/app/sidecar/src/main.ts"], env=sdk_env))
    deadline = time.monotonic() + 120
    while True:
        if any(child.poll() is not None for child in children):
            raise RuntimeError("dependency exited")
        try:
            with socket.create_connection(("127.0.0.1", 8788), timeout=1):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise TimeoutError("SDK startup deadline")
            time.sleep(0.25)
    children.append(subprocess.Popen(["/app/zz-watcher", "serve", "/etc/cwxmr/runtime.json"], env={"PATH": sdk_env["PATH"]}))
    while True:
        if any(child.poll() is not None for child in children):
            raise RuntimeError("runtime dependency exited")
        time.sleep(0.25)
except Exception:
    # No SDK, credential, key, destination or amount details in error output.
    print("Enclave runtime stopped", flush=True)
    stop()
