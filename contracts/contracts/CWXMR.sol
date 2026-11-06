// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {FHE, euint64, ebool} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";
import {ERC7984} from "@openzeppelin/confidential-contracts/token/ERC7984/ERC7984.sol";
import {FHESafeMath} from "@openzeppelin/confidential-contracts/utils/FHESafeMath.sol";

/// @notice 12-decimal confidential XMR. Bridge is the immutable, sole issuance authority.
contract CWXMR is ERC7984, ZamaEthereumConfig {
    address public immutable bridge;
    euint64 private _committedSupply;
    struct Burn { address user; euint64 actual; bool pending; }
    mapping(uint256 => Burn) public burns;
    error Unauthorized();
    error InvalidBurn();

    constructor() ERC7984("Confidential Wrapped XMR", "cwXMR", "") { bridge = msg.sender; }
    modifier onlyBridge() { require(msg.sender == bridge, Unauthorized()); _; }
    function decimals() public pure override returns (uint8) { return 12; }
    function committedSupply() external view returns (euint64) { return _committedSupply; }

    function bridgeMint(address to, euint64 requested) external onlyBridge returns (euint64 actual) {
        require(FHE.isSenderAllowed(requested), Unauthorized());
        (ebool success, euint64 committed) = FHESafeMath.tryIncrease(_committedSupply, requested);
        _committedSupply = committed;
        FHE.allowThis(committed);
        actual = _mint(to, FHE.select(success, requested, FHE.asEuint64(0)));
        FHE.allow(actual, bridge);
    }

    function bridgeBurn(uint256 id, address user, euint64 requested) external onlyBridge returns (euint64 actual) {
        require(burns[id].user == address(0), InvalidBurn());
        require(FHE.isSenderAllowed(requested), Unauthorized());
        actual = _burn(user, requested);
        burns[id] = Burn(user, actual, true);
        FHE.allow(actual, bridge);
    }

    function bridgeSettle(uint256 id) external onlyBridge {
        Burn storage b = burns[id];
        require(b.pending, InvalidBurn());
        b.pending = false;
        _committedSupply = FHE.sub(_committedSupply, b.actual);
        FHE.allowThis(_committedSupply);
    }

    /// @dev Pending burns reserve uint64 capacity, so restoring this exact result cannot overflow.
    function bridgeRefund(uint256 id) external onlyBridge returns (euint64 actual) {
        Burn storage b = burns[id];
        require(b.pending, InvalidBurn());
        b.pending = false;
        actual = _mint(b.user, b.actual);
        FHE.allow(actual, bridge);
    }
}
