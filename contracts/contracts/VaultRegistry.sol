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
    bytes32 public constant BINDING_TYPEHASH = keccak256("CWXMRNitroMintBinding(uint256 chainId,address registry,address bridge,bytes32 vaultId,address signingKey,address decryptKey,bytes32 tlsKeyHash,bytes32 authKeyHash,uint64 policyVersion,bytes32 mintDigest)");
    uint64 public constant MAX_DOCUMENT_AGE = 10 minutes;
    enum Status { None, Active, Draining, Suspended, Revoked, Retired }
    struct Keys { address decryptKey; bytes32 tlsKeyHash; bytes32 authKeyHash; }
    struct Record {
        address signingKey; address decryptKey; bytes32 tlsKeyHash; bytes32 authKeyHash;
        bytes32 pcrTuple; uint64 policyVersion; Status status;
    }
    struct MintEvidence { Keys keys; uint64 policyVersion; bytes output; bytes proof; }
    NitroVerifierAdapter public immutable adapter;
    address public immutable bridge;
    mapping(bytes32 => Record) public vaults;
    mapping(uint64 => mapping(bytes32 => bool)) public approvedPcrTuples;
    error InvalidEvidence();
    error InvalidLifecycle();
    error Unauthorized();
    event PcrPolicyUpdated(uint64 indexed policyVersion, bytes32 indexed pcrTuple, bool allowed);
    event VaultDiscovered(bytes32 indexed vaultId, address indexed signingKey, address decryptKey, uint64 policyVersion);
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

    /// @notice NSM user_data commits to the entire EIP-712 mint digest and key bundle.
    function bindingDigest(bytes32 vaultId, address signer, Keys calldata keys, uint64 version, bytes32 mintDigest)
        public view returns (bytes32) {
        return keccak256(abi.encode(BINDING_TYPEHASH, block.chainid, address(this), bridge, vaultId,
            signer, keys.decryptKey, keys.tlsKeyHash, keys.authKeyHash, version, mintDigest));
    }

    /// @notice Called once inside every deposit mint. No enrollment or renewable mint authority.
    function verifyMint(bytes32 vaultId, bytes32 mintDigest, uint256 nonce, MintEvidence calldata evidence)
        external nonReentrant {
        require(msg.sender == bridge, Unauthorized());
        VerifierJournal memory j = adapter.verify(evidence.output, evidence.proof);
        Keys calldata keys = evidence.keys;
        uint64 version = evidence.policyVersion;
        require(j.publicKey.length == 64 && keccak256(j.publicKey) == vaultId &&
            keys.decryptKey != address(0) && keys.tlsKeyHash != 0 && keys.authKeyHash != 0, InvalidEvidence());
        address signer = address(uint160(uint256(vaultId)));
        require(signer != address(0) && signer != keys.decryptKey, InvalidEvidence());
        require(j.nonce.length == 32 && keccak256(j.nonce) == keccak256(abi.encode(nonce)) &&
            j.userData.length == 32 && keccak256(j.userData) == keccak256(abi.encodePacked(
                bindingDigest(vaultId, signer, keys, version, mintDigest))), InvalidEvidence());
        require(j.timestamp != 0 && j.timestamp <= block.timestamp * 1000 &&
            uint256(j.timestamp) + MAX_DOCUMENT_AGE * 1000 >= block.timestamp * 1000, InvalidEvidence());
        bytes32 tuple = _pcrTuple(j.pcrs);
        require(approvedPcrTuples[version][tuple], InvalidEvidence());
        Record storage r = vaults[vaultId];
        if (r.status == Status.None) {
            r.signingKey = signer; r.decryptKey = keys.decryptKey;
            r.tlsKeyHash = keys.tlsKeyHash; r.authKeyHash = keys.authKeyHash;
            r.pcrTuple = tuple; r.policyVersion = version; r.status = Status.Active;
            emit VaultDiscovered(vaultId, signer, keys.decryptKey, version);
        } else {
            require(r.status == Status.Active, InvalidLifecycle());
            require(r.signingKey == signer && r.decryptKey == keys.decryptKey &&
                r.tlsKeyHash == keys.tlsKeyHash && r.authKeyHash == keys.authKeyHash, InvalidEvidence());
        }
        r.pcrTuple = tuple; r.policyVersion = version;
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
            approvedPcrTuples[r.policyVersion][r.pcrTuple] && adapter.configurationValid();
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
