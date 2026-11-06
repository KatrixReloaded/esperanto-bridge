// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {VerifierJournal, VerificationResult, ZkCoProcessorType} from "../interfaces/INitroEnclaveVerifier.sol";

/// @notice UNSAFE: accepts fabricated attestation journals without verifying any proof.
/// @dev Only for a separate Sepolia/stagenet exercise. Never a custody trust anchor.
contract UnsafeTestNitroVerifier {
    bytes32 public constant rootCert = keccak256("CWXMR_UNSAFE_TEST_ROOT");
    bytes32 public constant program = keccak256("CWXMR_UNSAFE_TEST_PROGRAM");
    bytes4 public constant proofSelector = 0x54535431;
    bool public constant unsafeTestOnly = true;

    constructor() {
        require(block.chainid == 11155111 || block.chainid == 31337, "TEST_NETWORK_ONLY");
    }

    function isVerifierIdSupported(ZkCoProcessorType, bytes32) external pure returns (bool) {
        return true;
    }

    function getZkVerifier(ZkCoProcessorType, bytes4) external view returns (address) {
        return address(this);
    }

    function verifyWithProgramId(bytes calldata output, ZkCoProcessorType, bytes32, bytes calldata)
        external pure returns (VerifierJournal memory journal)
    {
        journal = abi.decode(output, (VerifierJournal));
        journal.result = VerificationResult.Success;
    }
}
