// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {CWXMRSwap} from "../CWXMRSwap.sol";
import {FHE, externalEuint64, euint64, ebool} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

contract SwapReceiverMock is ZamaEthereumConfig {
    address public immutable token;
    uint8 public mode;
    address public pool;
    constructor(address t) { token = t; }
    function configure(uint8 m, address p) external { mode=m; pool=p; }
    function onConfidentialTransferReceived(address, address, euint64, bytes calldata) external returns(ebool ok) {
        require(msg.sender == token);
        if (mode == 2) revert("forward failed");
        if (mode == 3) {
            (bool success, bytes memory result) = pool.call(abi.encodeCall(CWXMRSwap.swap, (externalEuint64.wrap(bytes32(0)),externalEuint64.wrap(bytes32(0)),hex"",type(uint256).max,CWXMRSwap.PriceQuote(1,0,1),hex"")));
            require(!success && bytes4(result) == bytes4(keccak256("ReentrancyGuardReentrantCall()")), "wrong reentrancy rejection");
        }
        ok = FHE.asEbool(mode != 1);
        FHE.allowTransient(ok, token);
    }
}

// Test-only probe: exercise the real Bridge empty-proof path with omitted ACL grants.
import {externalEuint256, euint256} from "@fhevm/solidity/lib/FHE.sol";
import {IXMRInventoryBridge} from "../CWXMRBalancer.sol";
contract InventoryAclProbe is ZamaEthereumConfig {
    function forward(address target, externalEuint64 amount, externalEuint256[3] calldata words,
        bytes calldata proof, bytes32 vaultId, bool grantAmount, bool grantDestination) external {
        euint64 requested = FHE.fromExternal(amount, proof);
        if (grantAmount) FHE.allowTransient(requested, target);
        externalEuint256[3] memory destination;
        for (uint256 i; i < 3; ++i) {
            euint256 word = FHE.fromExternal(words[i], proof);
            if (grantDestination) FHE.allowTransient(word, target);
            destination[i] = externalEuint256.wrap(euint256.unwrap(word));
        }
        bytes32[] memory vaults = new bytes32[](1); vaults[0] = vaultId;
        IXMRInventoryBridge(target).requestRedemption(externalEuint64.wrap(euint64.unwrap(requested)),
            destination, "", bytes32(0), vaults);
    }
}
