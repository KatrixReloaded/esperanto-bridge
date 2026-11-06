// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {INitroEnclaveVerifier, VerifierJournal, VerificationResult, ZkCoProcessorType} from "./interfaces/INitroEnclaveVerifier.sol";

/// @notice Single-report adapter for Automata revision 65c4a4233029ea3bbe16110a80731fcfd47cf300.
/// @dev Configuration and bytecode pins fail closed on upstream changes. No fallback verifier.
contract NitroVerifierAdapter {
    INitroEnclaveVerifier public immutable verifier;
    bytes32 public immutable verifierCodeHash;
    bytes32 public immutable rootCert;
    bytes32 public immutable programId;
    ZkCoProcessorType public immutable coprocessor;
    bytes4 public immutable proofSelector;
    address public immutable zkVerifier;
    bytes32 public immutable zkVerifierCodeHash;

    error InvalidConfiguration();
    error InvalidAttestation();

    constructor(address verifier_, bytes32 expectedCodeHash, bytes32 root_, bytes32 program_,
        ZkCoProcessorType backend_, bytes4 selector_, address zk_, bytes32 expectedZkCodeHash) {
        require(verifier_.code.length != 0 && verifier_.codehash == expectedCodeHash &&
            zk_.code.length != 0 && zk_.codehash == expectedZkCodeHash && root_ != 0 && program_ != 0 &&
            (backend_ == ZkCoProcessorType.RiscZero || backend_ == ZkCoProcessorType.Succinct), InvalidConfiguration());
        verifier = INitroEnclaveVerifier(verifier_);
        verifierCodeHash = expectedCodeHash;
        rootCert = root_;
        programId = program_;
        coprocessor = backend_;
        proofSelector = selector_;
        zkVerifier = zk_;
        zkVerifierCodeHash = expectedZkCodeHash;
        require(configurationValid(), InvalidConfiguration());
    }

    function configurationValid() public view returns (bool) {
        return address(verifier).codehash == verifierCodeHash && zkVerifier.codehash == zkVerifierCodeHash &&
            verifier.rootCert() == rootCert && verifier.isVerifierIdSupported(coprocessor, programId) &&
            verifier.getZkVerifier(coprocessor, proofSelector) == zkVerifier;
    }

    function verify(bytes calldata output, bytes calldata proof) external returns (VerifierJournal memory journal) {
        require(configurationValid() && proof.length >= 4 && bytes4(proof[:4]) == proofSelector, InvalidConfiguration());
        journal = verifier.verifyWithProgramId(output, coprocessor, programId, proof);
        require(journal.result == VerificationResult.Success && journal.certs.length > 0 &&
            journal.certs[0] == rootCert && journal.trustedCertsPrefixLen > 0 &&
            journal.trustedCertsPrefixLen <= journal.certs.length, InvalidAttestation());
    }
}
