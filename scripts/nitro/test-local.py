#!/usr/bin/env python3
"""Native transport/TLS/security-boundary checks. No AWS calls, no mock production attestations."""
import concurrent.futures
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts/nitro" / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class LocalTests(unittest.TestCase):
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
const health=await connectPinned({json.dumps(endpoint)},{json.dumps(pin)});
assert.equal(health.native_development,true);assert.equal(health.bridge_actions_enabled,false);
await assert.rejects(connectPinned({json.dumps(endpoint)},'00'.repeat(32)), /TLS key differs/);
await assert.rejects(connectPinned({json.dumps(endpoint)},{json.dumps(pin)},'/attestation?challenge='+'00'.repeat(32)),/peer request rejected/);
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
