#!/usr/bin/env python3
"""Untrusted parent helper: store only ciphertext envelopes; relay the parent's IAM credentials."""
import argparse
import http.server
import json
import os
from pathlib import Path
import tempfile
import urllib.request


def credentials():
    # IMDSv2 credentials are not enclave wallet secrets. KMS authorization is recipient-restricted.
    base = "http://169.254.169.254/latest/"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    token = opener.open(urllib.request.Request(base + "api/token", method="PUT", headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"}), timeout=3).read().decode()
    headers = {"X-aws-ec2-metadata-token": token}
    roles = opener.open(urllib.request.Request(base + "meta-data/iam/security-credentials/", headers=headers), timeout=3).read().decode().splitlines()
    if len(roles) != 1 or not roles[0].replace("-", "").replace("_", "").isalnum():
        raise ValueError("expected one EC2 IAM role")
    result = json.load(opener.open(urllib.request.Request(base + "meta-data/iam/security-credentials/" + roles[0], headers=headers), timeout=3))
    return {name: result[name] for name in ("AccessKeyId", "SecretAccessKey", "Token")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", required=True)
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()
    path = Path(args.file).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # Never log requests, credentials or ciphertext payloads.
        def reply(self, status, data):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        def do_GET(self):
            try:
                if self.path == "/backup":
                    self.reply(200, path.read_bytes()) if path.exists() else self.reply(404, b"{}")
                elif self.path == "/credentials":
                    self.reply(200, json.dumps(credentials()).encode())
                else:
                    self.reply(404, b"{}")
            except Exception:
                self.reply(503, b'{"error":"host_transport_unavailable"}')
        def do_PUT(self):
            size = self.headers.get("Content-Length", "")
            if self.path != "/backup" or not size.isdecimal() or not 0 < int(size) <= 262144:
                self.reply(400, b"{}")
                return
            data = self.rfile.read(int(size))
            try:
                envelope = json.loads(data)
                if set(envelope) != {"version", "wrapped_key", "nonce", "tag", "ciphertext"} or envelope["version"] != 1:
                    raise ValueError("envelope")
                with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as output:
                    output.write(data)
                    output.flush()
                    os.fsync(output.fileno())
                    temporary = output.name
                os.replace(temporary, path)
                directory = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                self.reply(200, b"{}")
            except Exception:
                self.reply(400, b"{}")
    server = http.server.HTTPServer(("127.0.0.1", args.port), Handler)
    server.timeout = 10
    server.serve_forever()


if __name__ == "__main__":
    main()
