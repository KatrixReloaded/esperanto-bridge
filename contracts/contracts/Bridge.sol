// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FHE, externalEuint64, externalEuint256, euint64, euint256, ebool} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {CWXMR} from "./CWXMR.sol";
import {VaultRegistry} from "./VaultRegistry.sol";
import {NitroVerifierAdapter} from "./NitroVerifierAdapter.sol";

contract Bridge is EIP712, ReentrancyGuard, ZamaEthereumConfig {
    bytes32 public constant MINT_TYPEHASH = keccak256("Mint(bytes32 vaultId,bytes32 depositId,address recipient,bytes32 amountHandle,bytes32 inputProofHash,uint256 nonce,uint64 deadline)");
    bytes32 public constant CLAIM_TYPEHASH = keccak256("Claim(uint256 requestId,bytes32 vaultId,uint64 deadline)");
    bytes32 public constant SETTLE_TYPEHASH = keccak256("Settle(uint256 requestId,bytes32 vaultId,bytes32 paymentCommitment,uint64 deadline)");
    uint256 public constant MAX_ELIGIBLE_VAULTS = 16;
    uint64 public constant CANCEL_DELAY = 1 hours;
    CWXMR public immutable token;
    VaultRegistry public immutable registry;
    struct MintAuthorization {
        bytes32 vaultId; bytes32 depositId; address recipient; bytes32 amountHandle;
        bytes32 inputProofHash; uint256 nonce; uint64 deadline;
    }
    enum Status { None, Open, Assigned, Paid, Refunded }
    struct Redemption {
        address user; euint64 amount; euint256[3] destination; ebool nonzero;
        bytes32 feeTermsHash; uint64 cancelAfter; Status status; bytes32 assignee; bytes32 paymentCommitment;
    }
    mapping(bytes32 => bool) public consumedDeposits;
    mapping(bytes32 => mapping(uint256 => bool)) public usedMintNonces;
    mapping(bytes32 => euint64) public mintedAmounts;
    mapping(uint256 => Redemption) private _redemptions;
    mapping(uint256 => mapping(bytes32 => bool)) public eligible;
    mapping(bytes32 => uint256) public assignedRequests;
    uint256 public nextRequestId = 1;
    error Unauthorized();
    error InvalidInput();
    error AlreadyConsumed();
    error InvalidState();
    event DepositMinted(bytes32 indexed depositId, bytes32 indexed vaultId, address indexed recipient, euint64 actualAmount);
    event RedemptionRequested(uint256 indexed requestId, address indexed user, euint64 actualAmount,
        euint256[3] destination, ebool nonzero, bytes32 feeTermsHash, uint64 cancelAfter, bytes32[] eligibleVaults);
    event RedemptionAssigned(uint256 indexed requestId, bytes32 indexed vaultId);
    event RedemptionPaid(uint256 indexed requestId, bytes32 indexed vaultId, bytes32 paymentCommitment);
    event RedemptionRefunded(uint256 indexed requestId, address indexed user, euint64 actualAmount);

    constructor(address policyOwner, NitroVerifierAdapter adapter) EIP712("CWXMRBridge", "1") {
        token = new CWXMR();
        registry = new VaultRegistry(policyOwner, adapter, address(this));
    }

    /// @dev Input proof is scoped to this Bridge and msg.sender, including when submission is relayed.
    function confidentialMint(MintAuthorization calldata a, bytes calldata inputProof, bytes calldata signature,
        VaultRegistry.MintEvidence calldata evidence)
        external nonReentrant returns (euint64 actual) {
        require(a.recipient != address(0) && a.depositId != 0 && a.inputProofHash == keccak256(inputProof), InvalidInput());
        require(block.timestamp <= a.deadline &&
            ECDSA.recover(mintDigest(a), signature) == address(uint160(uint256(a.vaultId))), Unauthorized());
        require(!consumedDeposits[a.depositId] && !usedMintNonces[a.vaultId][a.nonce], AlreadyConsumed());
        registry.verifyMint(a.vaultId, mintDigest(a), a.nonce, evidence);
        consumedDeposits[a.depositId] = true; usedMintNonces[a.vaultId][a.nonce] = true;
        euint64 requested = FHE.fromExternal(externalEuint64.wrap(a.amountHandle), inputProof);
        FHE.allowTransient(requested, address(token));
        actual = token.bridgeMint(a.recipient, requested);
        FHE.allowThis(actual);
        FHE.allow(actual, a.recipient);
        FHE.allow(actual, registry.decryptKey(a.vaultId));
        mintedAmounts[a.depositId] = actual;
        emit DepositMinted(a.depositId, a.vaultId, a.recipient, actual);
    }

    function mintDigest(MintAuthorization calldata a) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(MINT_TYPEHASH, a)));
    }

    function requestRedemption(externalEuint64 amount, externalEuint256[3] calldata destination,
        bytes calldata inputProof, bytes32 feeTermsHash, bytes32[] calldata vaultIds)
        external nonReentrant returns (uint256 id) {
        require(vaultIds.length > 0 && vaultIds.length <= MAX_ELIGIBLE_VAULTS, InvalidInput());
        id = nextRequestId++;
        Redemption storage r = _redemptions[id];
        euint64 requested = FHE.fromExternal(amount, inputProof);
        FHE.allowTransient(requested, address(token));
        r.amount = token.bridgeBurn(id, msg.sender, requested);
        FHE.allowThis(r.amount); FHE.allow(r.amount, msg.sender);
        for (uint256 i; i < 3; ++i) {
            r.destination[i] = FHE.fromExternal(destination[i], inputProof);
            FHE.allowThis(r.destination[i]); FHE.allow(r.destination[i], msg.sender);
        }
        r.nonzero = FHE.ne(r.amount, uint64(0));
        FHE.allowThis(r.nonzero);
        // Reveals only whether an actual burn was positive. Claims must prove true using Zama KMS signatures.
        FHE.makePubliclyDecryptable(r.nonzero);
        bytes32 previous;
        for (uint256 i; i < vaultIds.length; ++i) {
            bytes32 vaultId = vaultIds[i];
            require(vaultId > previous && registry.authorized(vaultId, false), Unauthorized());
            previous = vaultId; eligible[id][vaultId] = true;
            address reader = registry.decryptKey(vaultId);
            FHE.allow(r.amount, reader);
            for (uint256 j; j < 3; ++j) FHE.allow(r.destination[j], reader);
        }
        r.user = msg.sender; r.status = Status.Open; r.feeTermsHash = feeTermsHash;
        r.cancelAfter = uint64(block.timestamp) + CANCEL_DELAY;
        emit RedemptionRequested(id, msg.sender, r.amount, r.destination, r.nonzero, feeTermsHash, r.cancelAfter, vaultIds);
    }

    function claim(uint256 id, bytes32 vaultId, uint64 deadline, bytes calldata signature, bytes calldata nonzeroProof)
        external nonReentrant {
        Redemption storage r = _redemptions[id];
        require(r.status == Status.Open && eligible[id][vaultId], InvalidState());
        _authorize(vaultId, false, deadline, keccak256(abi.encode(CLAIM_TYPEHASH, id, vaultId, deadline)), signature);
        bytes32[] memory handles = new bytes32[](1); handles[0] = ebool.unwrap(r.nonzero);
        FHE.checkSignatures(handles, abi.encode(true), nonzeroProof);
        r.status = Status.Assigned; r.assignee = vaultId;
        ++assignedRequests[vaultId];
        emit RedemptionAssigned(id, vaultId);
    }

    function settle(uint256 id, bytes32 vaultId, bytes32 paymentCommitment, uint64 deadline, bytes calldata signature)
        external nonReentrant {
        Redemption storage r = _redemptions[id];
        require(r.status == Status.Assigned && r.assignee == vaultId && paymentCommitment != 0, InvalidState());
        _authorize(vaultId, true, deadline,
            keccak256(abi.encode(SETTLE_TYPEHASH, id, vaultId, paymentCommitment, deadline)), signature);
        r.status = Status.Paid; r.paymentCommitment = paymentCommitment;
        --assignedRequests[vaultId];
        token.bridgeSettle(id);
        emit RedemptionPaid(id, vaultId, paymentCommitment);
    }

    function cancel(uint256 id) external nonReentrant {
        Redemption storage r = _redemptions[id];
        require(r.status == Status.Open && r.user == msg.sender && block.timestamp >= r.cancelAfter, InvalidState());
        r.status = Status.Refunded;
        euint64 actual = token.bridgeRefund(id);
        FHE.allowThis(actual); FHE.allow(actual, r.user);
        emit RedemptionRefunded(id, r.user, actual);
    }
    function redemptions(uint256 id) external view returns (Redemption memory) { return _redemptions[id]; }

    function _authorize(bytes32 vaultId, bool completion, uint64 deadline, bytes32 structHash, bytes calldata signature)
        private view {
        require(block.timestamp <= deadline && registry.authorized(vaultId, completion), Unauthorized());
        require(ECDSA.recover(_hashTypedDataV4(structHash), signature) == registry.signingKey(vaultId), Unauthorized());
    }
}
