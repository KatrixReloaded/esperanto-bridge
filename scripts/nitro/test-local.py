#!/usr/bin/env python3
"""Native transport/TLS/security-boundary checks. No AWS calls, no mock production attestations."""
import concurrent.futures
import ast
import importlib.util
import json
import os
import re
import shlex
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/nitro" / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class LocalTests(unittest.TestCase):
    def test_database_and_proof_relays_outlive_prover_request(self):
        # PostgreSQL holds the cooperative lease while the proof is running. Both TLS
        # transport hops must survive that idle period, not just the proof forwarding path.
        client = (ROOT / "service/crates/watcher/src/prover.rs").read_text()
        deadline = max(map(int, re.findall(r"Duration::from_secs\((\d+)\)", client)))
        tree = ast.parse((ROOT / "enclave/init.py").read_text())
        arguments = [ast.literal_eval(n) for n in ast.walk(tree) if isinstance(n, ast.List)
                     and n.elts and all(isinstance(x, ast.Constant) for x in n.elts)]
        parent = (ROOT / "scripts/nitro/run-host.sh").read_text().splitlines()
        for port in ("8446", "8447"):
            inside = next(a for a in arguments if a[:3] == ["tcp-vsock", "--listen", port])
            outside = shlex.split(next(line for line in parent if f"--listen {port} " in line))
            for args in (inside, outside):
                self.assertGreater(int(args[args.index("--idle") + 1]), deadline)

    def test_forwarding_idle_deadline_is_bounded(self):
        forward = module("forward_idle", "forward.py")
        source, left = socket.socketpair()
        right, destination = socket.socketpair()
        with source, destination:
            with self.assertRaises(TimeoutError):
                forward.relay(left, right, idle=0.01)
        command = ["python3", ROOT / "scripts/nitro/forward.py", "tcp-vsock", "--listen", "10000", "--target", "10001", "--idle", "601"]
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_connect_gateway_port_requires_exact_allowlist(self):
        forward = module("forward", "forward.py")
        for authority, allowed, permitted in [("nym.test:9001", ["nym.test:9001"], True),
                                               ("nym.test:9000", ["nym.test:9001"], False),
                                               ("nym.test:9001", ["nym.test"], False),
                                               ("nym.test:443", ["nym.test"], True)]:
            source, client = socket.socketpair()
            with source, client, patch.object(forward.socket, "create_connection") as connect, patch.object(forward, "relay"):
                source.sendall(f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode())
                if permitted:
                    forward.tunnel(client, allowed)
                    connect.assert_called_once_with(("nym.test", int(authority.rsplit(":", 1)[1])), timeout=10)
                    self.assertIn(b"200", source.recv(100))
                else:
                    with self.assertRaises(ValueError):
                        forward.tunnel(client, allowed)
                    connect.assert_not_called()
                    self.assertIn(b"403", source.recv(100))

    def test_forwarding_preserves_bytes_and_half_closes(self):
        forward = module("forward", "forward.py")
        source, left = socket.socketpair()
        right, destination = socket.socketpair()
        one, two = os.urandom(300000), os.urandom(320000)
        def send(sock, data):
            sock.sendall(data)
            sock.shutdown(socket.SHUT_WR)
        def receive(sock):
            output = bytearray()
            while True:
                chunk = sock.recv(32768)
                if not chunk:
                    return bytes(output)
                output.extend(chunk)
        with source, destination, concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            relay = pool.submit(forward.relay, left, right, 5)
            writers = [pool.submit(send, source, one), pool.submit(send, destination, two)]
            received_one, received_two = pool.submit(receive, destination), pool.submit(receive, source)
            self.assertEqual(received_one.result(timeout=10), one)
            self.assertEqual(received_two.result(timeout=10), two)
            for writer in writers:
                writer.result(timeout=10)
            relay.result(timeout=10)

    def test_debug_and_missing_measurements_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "describe.json"
            path.write_text(json.dumps({"Measurements": {f"PCR{i}": "01" * 48 for i in range(3)}}))
            script = ROOT / "scripts/nitro/measurements.py"
            self.assertEqual(subprocess.run(["python3", script, path], capture_output=True).returncode, 0)
            path.write_text(json.dumps({"Measurements": {f"PCR{i}": "00" * 48 for i in range(3)}}))
            self.assertNotEqual(subprocess.run(["python3", script, path], capture_output=True).returncode, 0)
            path.write_text('{"Measurements":{}}')
            self.assertNotEqual(subprocess.run(["python3", script, path], capture_output=True).returncode, 0)

    def test_known_key_and_root_policy_bypasses_rejected(self):
        policy = module("policy", "inspect-kms-policy.py")
        role = "arn:aws:iam::123456789012:role/Parent"
        pcrs = {f"PCR{i}": "01" * 48 for i in range(3)}
        statements = [
            {"Effect": "Allow", "Principal": {"AWS": role}, "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
             "Condition": {"StringEqualsIgnoreCase": {f"kms:RecipientAttestation:PCR{i}": pcrs[f"PCR{i}"] for i in range(3)}}},
            {"Effect": "Deny", "Principal": {"AWS": role}, "Action": ["kms:Decrypt", "kms:GenerateDataKey"],
             "Condition": {"Null": {"kms:RecipientAttestation:ImageSha384": "true"}}},
            {"Effect": "Deny", "Principal": {"AWS": role}, "Action": ["kms:Encrypt", "kms:ReEncrypt*", "kms:CreateGrant", "kms:PutKeyPolicy", "kms:GenerateDataKeyWithoutPlaintext"]},
        ]
        policy.inspect({"Statement": statements}, role, pcrs)
        administrator = "arn:aws:iam::123456789012:root"
        admin = {"Effect": "Allow", "Principal": {"AWS": administrator},
                 "Action": ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy"]}
        with self.assertRaises(SystemExit):
            policy.inspect({"Statement": [*statements, admin]}, role, pcrs)
        policy.inspect({"Statement": [*statements, admin]}, role, pcrs, administrator)
        for action in ["kms:*", "kms:Decrypt", "kms:GenerateDataKey", "kms:CreateGrant"]:
            with self.assertRaises(SystemExit):
                policy.inspect({"Statement": [*statements, {**admin, "Action": action}]}, role, pcrs, administrator)
        for bypass in [
            {"Effect": "Allow", "Principal": {"AWS": role}, "Action": "kms:Encrypt"},
            {"Effect": "Allow", "Principal": {"AWS": ["arn:aws:iam::123456789012:root"]}, "Action": "kms:*"},
            {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "kms:*"},
        ]:
            with self.assertRaises(SystemExit):
                policy.inspect({"Statement": [*statements, bypass]}, role, pcrs)
        invalid = json.loads(json.dumps(statements))
        invalid[0]["Condition"]["StringEqualsIgnoreCase"]["kms:RecipientAttestation:PCR0"] = "00" * 48
        with self.assertRaises(SystemExit):
            policy.inspect({"Statement": invalid}, role, pcrs)

    def test_live_native_tls_possession_and_wrong_pin(self):
        # NODE_BIN points to a functional installed Node >=22; no SDK network call is made.
        node = os.environ.get("NODE_BIN", "node")
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        binary = Path(os.environ.get("WATCHER_BIN", str(ROOT / "service/target/debug/zz-watcher")))
        process = subprocess.Popen([binary, "serve-dev", str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            ready = json.loads(process.stdout.readline())
            self.assertTrue(ready["native_development"])
            self.assertFalse(ready["bridge_actions_enabled"])
            endpoint = f"https://127.0.0.1:{port}"
            pin = ready["identity"]["tls_key_hash"]
            code = f"""
import {{ connectPinned }} from {json.dumps((ROOT/'scripts/nitro/verify-peer.mjs').as_uri())};
import assert from 'node:assert/strict';
import tls from 'node:tls';
const health=await connectPinned({json.dumps(endpoint)},{json.dumps(pin)});
assert.equal(health.native_development,true);assert.equal(health.bridge_actions_enabled,false);
await assert.rejects(connectPinned({json.dumps(endpoint)},'00'.repeat(32)), /TLS key differs/);
const identity=await connectPinned({json.dumps(endpoint)},{json.dumps(pin)},'/identity');
assert.equal(identity.tls_key_hash,{json.dumps(pin)});
await assert.rejects(connectPinned({json.dumps(endpoint)},{json.dumps(pin)},'/attestation?nonce='+'00'.repeat(32)),/peer request rejected/);
await assert.rejects(connectPinned({json.dumps(endpoint)},{json.dumps(pin)},'/attestation?challenge='+'00'.repeat(32)),/peer request rejected/);
await assert.rejects(connectPinned({json.dumps(endpoint)},{json.dumps(pin)},'/mint-attestation'),/peer request rejected/);
async function closed(request) {{
  return await new Promise((resolve,reject) => {{
    const s=tls.connect({{host:'127.0.0.1',port:{port},rejectUnauthorized:false}},()=>s.write(request));
    let data=''; s.on('data',x=>data+=x); s.on('end',()=>resolve(data)); s.on('error',reject);
  }});
}}
const payload=JSON.stringify({{recipient:'0x'+'11'.repeat(20),nonce:'0x'+'22'.repeat(32)}});
for (const request of [
  `POST /v1/deposit-intents HTTP/1.1\\r\\nHost: localhost\\r\\nContent-Type: application/json\\r\\nContent-Length: ${{Buffer.byteLength(payload)}}\\r\\n\\r\\n${{payload}}`,
  `GET /v1/deposit-intents/0x${{'33'.repeat(32)}} HTTP/1.1\\r\\nHost: localhost\\r\\n\\r\\n`
]) {{ const response=await closed(request); assert.ok(response.startsWith('HTTP/1.1 503')); assert.ok(!response.includes('depositAddress')); }}
"""
            result = subprocess.run([node, "--input-type=module", "-"], input=code, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
        finally:
            process.terminate()
            process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
