// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {NitroVerifierAdapter} from "./NitroVerifierAdapter.sol";
import {VerifierJournal, Pcr} from "./interfaces/INitroEnclaveVerifier.sol";

interface IBridgeAssignments {
    function assignedRequests(bytes32 vaultId) external view returns (uint256);
}

contract VaultRegistry is Ownable, ReentrancyGuard {
    bytes32 public constant BINDING_TYPEHASH = keccak256("CWXMRNitroBinding(uint256 chainId,address registry,address bridge,bytes32 vaultId,address signingKey,address decryptKey,bytes32 tlsKeyHash,bytes32 authKeyHash,uint64 policyVersion,bytes32 challenge)");
    uint64 public constant CHALLENGE_LIFETIME = 10 minutes;
    uint64 public constant MAX_DOCUMENT_AGE = 10 minutes;
    uint64 public constant ATTESTATION_LIFETIME = 1 days;
    enum Status { None, Active, Draining, Suspended, Revoked, Retired }
    struct Keys { address decryptKey; bytes32 tlsKeyHash; bytes32 authKeyHash; }
    struct Record {
        address signingKey; address decryptKey; bytes32 tlsKeyHash; bytes32 authKeyHash;
        bytes32 pcrTuple; uint64 policyVersion; uint64 expiresAt; Status status;
    }
    struct Challenge { bytes32 vaultId; address requester; uint64 issuedAt; bool consumed; }
    NitroVerifierAdapter public immutable adapter;
    address public immutable bridge;
    mapping(bytes32 => Record) public vaults;
    mapping(bytes32 => Challenge) public challenges;
    mapping(uint64 => mapping(bytes32 => bool)) public approvedPcrTuples;
    uint256 private _challengeCounter;
    error InvalidEvidence();
    error InvalidLifecycle();
    error Unauthorized();
    event ChallengeIssued(bytes32 indexed challenge, bytes32 indexed vaultId, address indexed requester, uint64 issuedAt);
    event PcrPolicyUpdated(uint64 indexed policyVersion, bytes32 indexed pcrTuple, bool allowed);
    event VaultAttested(bytes32 indexed vaultId, address indexed signingKey, address decryptKey, uint64 policyVersion, uint64 expiresAt);
    event VaultStatusChanged(bytes32 indexed vaultId, Status status);

    constructor(address owner_, NitroVerifierAdapter adapter_, address bridge_) Ownable(owner_) {
        require(address(adapter_).code.length > 0 && bridge_ != address(0), InvalidEvidence());
        adapter = adapter_; bridge = bridge_;
    }

    function setPcrPolicy(uint64 version, bytes32 tuple, bool allowed) external onlyOwner {
        require(version != 0 && tuple != 0, InvalidEvidence());
        approvedPcrTuples[version][tuple] = allowed;
        emit PcrPolicyUpdated(version, tuple, allowed);
    }

    function issueChallenge(bytes32 vaultId, bytes32 salt) external returns (bytes32 challenge) {
        require(vaultId != 0, InvalidEvidence());
        challenge = keccak256(abi.encode(block.chainid, address(this), vaultId, msg.sender, salt, ++_challengeCounter));
        challenges[challenge] = Challenge(vaultId, msg.sender, uint64(block.timestamp), false);
        emit ChallengeIssued(challenge, vaultId, msg.sender, uint64(block.timestamp));
    }

    function bindingDigest(bytes32 vaultId, address signer, Keys calldata keys, uint64 version, bytes32 challenge)
        public view returns (bytes32) {
        return keccak256(abi.encode(BINDING_TYPEHASH, block.chainid, address(this), bridge, vaultId,
            signer, keys.decryptKey, keys.tlsKeyHash, keys.authKeyHash, version, challenge));
    }

    /// @notice Registers or refreshes the same immutable key bundle; refresh never changes lifecycle.
    function attest(bytes32 vaultId, Keys calldata keys, uint64 version, bytes32 challenge,
        bytes calldata output, bytes calldata proof) external nonReentrant {
        Challenge storage c = challenges[challenge];
        require(!c.consumed && c.requester == msg.sender && c.vaultId == vaultId && c.issuedAt != 0 &&
            block.timestamp <= uint256(c.issuedAt) + CHALLENGE_LIFETIME, InvalidEvidence());
        c.consumed = true;
        VerifierJournal memory j = adapter.verify(output, proof);
        require(j.publicKey.length == 64 && keccak256(j.publicKey) == vaultId &&
            keys.decryptKey != address(0) && keys.tlsKeyHash != 0 && keys.authKeyHash != 0, InvalidEvidence());
        address signer = address(uint160(uint256(vaultId)));
        require(signer != address(0) && signer != keys.decryptKey, InvalidEvidence());
        require(j.nonce.length == 32 && keccak256(j.nonce) == keccak256(abi.encodePacked(challenge)) &&
            j.userData.length == 32 && keccak256(j.userData) == keccak256(abi.encodePacked(
                bindingDigest(vaultId, signer, keys, version, challenge))), InvalidEvidence());
        require(j.timestamp >= uint256(c.issuedAt) * 1000 && j.timestamp <= block.timestamp * 1000 &&
            uint256(j.timestamp) + MAX_DOCUMENT_AGE * 1000 >= block.timestamp * 1000, InvalidEvidence());
        bytes32 tuple = _pcrTuple(j.pcrs);
        require(approvedPcrTuples[version][tuple], InvalidEvidence());
        Record storage r = vaults[vaultId];
        if (r.status == Status.None) {
            r.signingKey = signer; r.decryptKey = keys.decryptKey;
            r.tlsKeyHash = keys.tlsKeyHash; r.authKeyHash = keys.authKeyHash; r.status = Status.Active;
        } else {
            require(r.status == Status.Active || r.status == Status.Draining, InvalidLifecycle());
            require(r.signingKey == signer && r.decryptKey == keys.decryptKey &&
                r.tlsKeyHash == keys.tlsKeyHash && r.authKeyHash == keys.authKeyHash, InvalidEvidence());
        }
        r.pcrTuple = tuple; r.policyVersion = version;
        r.expiresAt = uint64(j.timestamp / 1000) + ATTESTATION_LIFETIME;
        emit VaultAttested(vaultId, signer, keys.decryptKey, version, r.expiresAt);
    }

    function setStatus(bytes32 vaultId, Status status) external {
        Record storage r = vaults[vaultId];
        require(r.status != Status.None && r.status != Status.Revoked && r.status != Status.Retired, InvalidLifecycle());
        if (msg.sender == r.signingKey) {
            require(status == Status.Draining && r.status == Status.Active, InvalidLifecycle());
        } else {
            require(msg.sender == owner(), Unauthorized());
            require(status == Status.Suspended || status == Status.Revoked ||
                (status == Status.Retired && r.status == Status.Draining &&
                    IBridgeAssignments(bridge).assignedRequests(vaultId) == 0), InvalidLifecycle());
        }
        r.status = status;
        emit VaultStatusChanged(vaultId, status);
    }

    function authorized(bytes32 vaultId, bool completion) public view returns (bool) {
        Record storage r = vaults[vaultId];
        return (r.status == Status.Active || (completion && r.status == Status.Draining)) &&
            block.timestamp <= r.expiresAt && approvedPcrTuples[r.policyVersion][r.pcrTuple] && adapter.configurationValid();
    }
    function signingKey(bytes32 vaultId) external view returns (address) { return vaults[vaultId].signingKey; }
    function decryptKey(bytes32 vaultId) external view returns (address) { return vaults[vaultId].decryptKey; }

    function _pcrTuple(Pcr[] memory pcrs) private pure returns (bytes32) {
        bytes[3] memory values;
        uint8 seen;
        for (uint256 i; i < pcrs.length; ++i) {
            Pcr memory p = pcrs[i];
            if (p.index > 2) continue;
            uint8 mask = uint8(1 << p.index);
            require((seen & mask) == 0 && (p.value.first != 0 || p.value.second != 0), InvalidEvidence());
            seen |= mask;
            values[p.index] = abi.encodePacked(p.value.first, p.value.second);
        }
        require(seen == 7, InvalidEvidence());
        return keccak256(bytes.concat(values[0], values[1], values[2]));
    }
}
