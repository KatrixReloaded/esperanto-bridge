#!/usr/bin/env python3
"""Reject missing/debug PCRs. describe-eif JSON is a build artifact, not live attestation."""
import json
import sys
value = json.load(open(sys.argv[1]))
pcrs = value["Measurements"]
result = {}
for index in range(3):
    name = f"PCR{index}"
    raw = bytes.fromhex(pcrs[name])
    if len(raw) != 48 or not any(raw):
        raise SystemExit(f"Invalid or debug {name}")
    result[name] = raw.hex()
if len(sys.argv) == 3:
    approved = json.load(open(sys.argv[2]))
    if result != approved:
        raise SystemExit("EIF differs from approved PCR0/PCR1/PCR2")
print(json.dumps(result, sort_keys=True, indent=2))
