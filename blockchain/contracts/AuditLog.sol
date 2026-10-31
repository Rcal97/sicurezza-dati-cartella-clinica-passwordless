// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {ConsentRegistry} from "./ConsentRegistry.sol";

/// @title Registro di audit
/// @notice Registra, in sola aggiunta, ogni accesso a una cartella clinica.
contract AuditLog is AccessControl {
    bytes32 public constant RECORDER_ROLE = keccak256("RECORDER_ROLE");

    enum Outcome {
        Denied,
        Granted
    }

    ConsentRegistry public immutable consentRegistry;
    uint256 public totalEntries;

    event AccessRecorded(
        uint256 indexed entryId,
        address indexed patient,
        address indexed accessor,
        Outcome outcome,
        bytes32 recordHash
    );

    error ConsentNotValid();

    constructor(address admin, ConsentRegistry registry) {
        consentRegistry = registry;
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice Registra un accesso. Solo il backend (RECORDER_ROLE).
    /// @param recordHash hash dei dettagli dell'accesso, conservati off-chain
    function recordAccess(
        address patient,
        address accessor,
        Outcome outcome,
        bytes32 recordHash
    ) external onlyRole(RECORDER_ROLE) returns (uint256 entryId) {
        if (outcome == Outcome.Granted && !consentRegistry.isConsentValid(patient, accessor)) {
            revert ConsentNotValid();
        }
        entryId = ++totalEntries;
        emit AccessRecorded(entryId, patient, accessor, outcome, recordHash);
    }
}
