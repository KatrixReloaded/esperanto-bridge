// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FHE, externalEuint64, externalEuint256, euint64, euint256, ebool} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {IERC7984Receiver} from "@openzeppelin/confidential-contracts/interfaces/IERC7984Receiver.sol";
import {ERC165} from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

interface IXMRInventoryBridge {
    function token() external view returns (address);
    function requestRedemption(externalEuint64 amount, externalEuint256[3] calldata destination,
        bytes calldata proof, bytes32 feeTermsHash, bytes32[] calldata vaultIds) external returns (uint256);
    function cancel(uint256 requestId) external;
}

/// @notice Holds cwXMR inventory; the service can only redeem to the fixed encrypted destination.
/// @dev The deployer must authenticate the destination plaintext during one-time setup before funding.
contract CWXMRBalancer is IERC7984Receiver, ERC165, ZamaEthereumConfig {
    address public immutable token;
    IXMRInventoryBridge public immutable bridge;
    address public immutable service;
    address public immutable setupAuthority;
    bool public initialized;
    euint256[3] public destination;
    struct Operation { bytes32 terms; uint256 redeemId; }
    mapping(bytes32 => Operation) public operations;
    error Unauthorized();
    error InvalidConfiguration();
    error AlreadyInitialized();
    error NotInitialized();
    error OperationConflict();
    error UnknownOperation();
    event DestinationInitialized();
    event RedemptionRequested(bytes32 indexed operationId, uint256 indexed redeemId);

    constructor(address bridge_, address service_) {
        require(bridge_.code.length != 0 && service_ != address(0), InvalidConfiguration());
        bridge = IXMRInventoryBridge(bridge_);
        address token_ = bridge.token();
        require(token_.code.length != 0, InvalidConfiguration());
        token = token_;
        service = service_;
        setupAuthority = msg.sender;
    }

    /// @dev Proof binds (this balancer, deployer). There is no destination replacement path.
    function initializeDestination(externalEuint256[3] calldata words, bytes calldata proof) external {
        require(msg.sender == setupAuthority, Unauthorized());
        require(!initialized, AlreadyInitialized());
        require(proof.length != 0, InvalidConfiguration());
        for (uint256 i; i < 3; ++i) {
            destination[i] = FHE.fromExternal(words[i], proof);
            FHE.allowThis(destination[i]);
        }
        initialized = true;
        emit DestinationInitialized();
    }

    /// @dev Amount proof binds (this balancer, service), not (bridge, service).
    /// Bridge's empty-proof path accepts these already verified and ACL-authorized handles.
    function redeem(bytes32 operationId, externalEuint64 amount, bytes calldata proof,
        bytes32 feeTermsHash, bytes32[] calldata vaultIds) external returns (uint256) {
        require(msg.sender == service, Unauthorized());
        require(initialized, NotInitialized());
        bytes32 terms = keccak256(abi.encode(amount, proof, feeTermsHash, vaultIds));
        Operation storage operation = operations[operationId];
        if (operation.redeemId != 0) {
            require(operation.terms == terms, OperationConflict());
            return operation.redeemId;
        }
        // A nonempty proof verifies the uint64 type as well as sender/contract binding.
        require(proof.length != 0, InvalidConfiguration());
        euint64 requested = FHE.fromExternal(amount, proof);
        FHE.allowTransient(requested, address(bridge));
        externalEuint256[3] memory pinned;
        for (uint256 i; i < 3; ++i) {
            FHE.allowTransient(destination[i], address(bridge));
            pinned[i] = externalEuint256.wrap(euint256.unwrap(destination[i]));
        }
        operation.terms = terms;
        uint256 id = bridge.requestRedemption(externalEuint64.wrap(euint64.unwrap(requested)), pinned,
            "", feeTermsHash, vaultIds);
        operation.redeemId = id;
        emit RedemptionRequested(operationId, id);
        return id;
    }

    /// @notice Return an expired, unassigned bridge burn to this inventory receiver.
    function cancel(bytes32 operationId) external {
        require(msg.sender == service, Unauthorized());
        uint256 id = operations[operationId].redeemId;
        require(id != 0, UnknownOperation());
        bridge.cancel(id);
    }

    function onConfidentialTransferReceived(address, address, euint64 amount, bytes calldata)
        external returns (ebool accepted)
    {
        require(msg.sender == token, Unauthorized());
        require(initialized, NotInitialized());
        require(FHE.isAllowed(amount, address(this)), Unauthorized());
        accepted = FHE.asEbool(true);
        FHE.allowTransient(accepted, token);
    }

    function supportsInterface(bytes4 id) public view override returns (bool) {
        return id == type(IERC7984Receiver).interfaceId || super.supportsInterface(id);
    }
}
