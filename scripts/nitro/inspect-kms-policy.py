#!/usr/bin/env python3
"""Conservative structural review of a concrete AWS get-key-policy response.
This is not a complete AWS IAM/grant/role-assumption authorization evaluator.
"""
import argparse
import fnmatch
import json
import re


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def action_matches(statement, action):
    patterns = statement.get("Action", [])
    if isinstance(patterns, str):
        patterns = [patterns]
    return any(fnmatch.fnmatchcase(action.lower(), pattern.lower()) for pattern in patterns)


def principals(statement):
    value = statement.get("Principal", {})
    value = value.get("AWS", []) if isinstance(value, dict) else value
    return [value] if isinstance(value, str) else value


def includes_parent(statement, parent_arn):
    values = principals(statement)
    return "*" in values or parent_arn in values


ADMIN_ACTIONS = {
    "kms:DescribeKey", "kms:GetKeyPolicy", "kms:PutKeyPolicy", "kms:ListKeyPolicies",
    "kms:EnableKey", "kms:DisableKey", "kms:EnableKeyRotation", "kms:DisableKeyRotation",
    "kms:GetKeyRotationStatus", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
    "kms:TagResource", "kms:UntagResource",
}


def inspect(policy, parent_arn, pcrs, reviewed_administrator=None):
    if reviewed_administrator:
        require(re.fullmatch(r"arn:aws:iam::[0-9]{12}:(root|role/[A-Za-z0-9+=,.@_/-]+)", reviewed_administrator),
                "Reviewed administrator must be an exact IAM ARN")
    statements = policy["Statement"]
    require(isinstance(statements, list), "Statement must be a list")
    forbidden = ["kms:Encrypt", "kms:ReEncryptFrom", "kms:ReEncryptTo", "kms:CreateGrant",
                 "kms:PutKeyPolicy", "kms:GenerateDataKeyWithoutPlaintext"]
    for statement in statements:
        require("NotPrincipal" not in statement and "NotAction" not in statement,
                "Negative AWS selectors require explicit authorization review")
        if statement.get("Effect") != "Allow":
            continue
        values = principals(statement)
        if reviewed_administrator and values == [reviewed_administrator]:
            # Explicitly reviewed policy administration is a trust boundary, not cryptographic
            # permission. Account-root statements delegate these listed administrative actions
            # through IAM too; never accept kms:* or key-use/grant actions in this exception.
            actions = statement.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            require(reviewed_administrator != parent_arn and actions and set(actions) <= ADMIN_ACTIONS,
                    "Reviewed administrator may have only exact administrative actions")
            continue
        require(isinstance(values, list) and all(isinstance(value, str) and value != "*" and not value.endswith(":root") for value in values),
                "Wildcard/root IAM delegation requires explicit review")
        if not includes_parent(statement, parent_arn):
            # A second cryptographic principal could expose a host-known wrapped data key.
            for action in [*forbidden, "kms:Decrypt", "kms:GenerateDataKey"]:
                if action != "kms:PutKeyPolicy":
                    require(not action_matches(statement, action), "Alternate cryptographic/grant principal requires explicit review")
            continue
        for action in forbidden:
            require(not action_matches(statement, action), f"Parent allow includes {action}")
        if action_matches(statement, "kms:Decrypt") or action_matches(statement, "kms:GenerateDataKey"):
            conditions = statement.get("Condition", {}).get("StringEqualsIgnoreCase", {})
            for index in range(3):
                actual = conditions.get(f"kms:RecipientAttestation:PCR{index}", "")
                expected = pcrs[f"PCR{index}"]
                require(isinstance(actual, str) and len(actual) == 96 and actual.lower() == expected.lower() and int(actual, 16) > 0,
                        "Missing exact approved nonzero PCR condition")
    for action in ["kms:Decrypt", "kms:GenerateDataKey"]:
        present = any(statement.get("Effect") == "Deny" and includes_parent(statement, parent_arn)
                      and action_matches(statement, action)
                      and statement.get("Condition", {}).get("Null", {}).get("kms:RecipientAttestation:ImageSha384") in ("true", True)
                      for statement in statements)
        require(present, f"Missing parent plaintext {action} deny")
    for action in forbidden:
        present = any(statement.get("Effect") == "Deny" and includes_parent(statement, parent_arn)
                      and action_matches(statement, action) and not statement.get("Condition")
                      for statement in statements)
        require(present, f"Missing unconditional parent deny for {action}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy")
    parser.add_argument("parent_role_arn")
    parser.add_argument("approved_pcrs")
    parser.add_argument("--reviewed-administrator", help="Exact explicitly reviewed policy administrator ARN; permits only administrative actions, never cryptographic use or grants")
    args = parser.parse_args()
    policy = json.load(open(args.policy))
    if "Policy" in policy:
        policy = json.loads(policy["Policy"])
    inspect(policy, args.parent_role_arn, json.load(open(args.approved_pcrs)), args.reviewed_administrator)
    print("Structural recipient restrictions present; review all administrators, IAM policies and grants separately")


if __name__ == "__main__":
    main()
