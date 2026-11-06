// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {VerifierJournal, ZkCoProcessorType} from "../interfaces/INitroEnclaveVerifier.sol";
/// @dev TEST ONLY: cannot be constructed on a shared network, never a production trust anchor.
contract MockNitroVerifier {
    bytes32 public rootCert = keccak256("test-root");
    bytes32 public program = keccak256("test-program");
    bool public enabled = true;
    address public route;
    constructor() { require(block.chainid == 31337, "LOCAL_ONLY"); route = address(this); }
    function setEnabled(bool value) external { enabled = value; }
    function setRoot(bytes32 value) external { rootCert = value; }
    function setRoute(address value) external { route = value; }
    function isVerifierIdSupported(ZkCoProcessorType, bytes32 p) external view returns (bool) { return enabled && p == program; }
    function getZkVerifier(ZkCoProcessorType, bytes4) external view returns (address) { return route; }
    function verifyWithProgramId(bytes calldata output, ZkCoProcessorType, bytes32 p, bytes calldata proof)
        external view returns (VerifierJournal memory) {
        require(enabled && p == program && keccak256(proof) == keccak256(abi.encodePacked(bytes4(0x12345678), keccak256(output))), "BAD_PROOF");
        return abi.decode(output, (VerifierJournal));
    }
}
