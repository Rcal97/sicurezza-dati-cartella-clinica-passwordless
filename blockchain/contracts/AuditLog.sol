// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {ConsentRegistry} from "./ConsentRegistry.sol";

/// @title Registro di audit
/// @notice Registra, in sola aggiunta, ogni accesso a una cartella clinica.
/// @dev L'amministratore assegna i ruoli RECORDER ed EMERGENCY. Il suo ruolo segue le regole
///      di AccessControlDefaultAdminRules: passaggio di consegne in due fasi e con un ritardo,
///      visibile sulla catena prima che abbia effetto.
contract AuditLog is AccessControlDefaultAdminRules {
    bytes32 public constant RECORDER_ROLE = keccak256("RECORDER_ROLE");
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    /// @notice Attesa minima prima che un nuovo amministratore possa subentrare.
    uint48 public constant ADMIN_TRANSFER_DELAY = 2 days;

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
        ConsentRegistry.Purpose purpose,
        Outcome outcome,
        bytes32 recordHash
    );

    event EmergencyAccess(
        uint256 indexed entryId,
        address indexed patient,
        address indexed accessor,
        bytes32 reasonHash,
        bytes32 recordHash
    );

    error ConsentNotValid();
    error NotEmergencyStaff(address accessor);
    error MissingReason();

    constructor(address admin, ConsentRegistry registry) AccessControlDefaultAdminRules(ADMIN_TRANSFER_DELAY, admin) {
        consentRegistry = registry;
    }

    /// @notice Registra un accesso ordinario. Solo il backend (RECORDER_ROLE).
    /// @param recordHash hash dei dettagli dell'accesso, conservati off-chain
    function recordAccess(
        address patient,
        address accessor,
        ConsentRegistry.Purpose purpose,
        Outcome outcome,
        bytes32 recordHash
    ) external onlyRole(RECORDER_ROLE) returns (uint256 entryId) {
        if (
            outcome == Outcome.Granted &&
            !consentRegistry.isConsentValid(patient, accessor, purpose)
        ) {
            revert ConsentNotValid();
        }
        entryId = ++totalEntries;
        emit AccessRecorded(entryId, patient, accessor, purpose, outcome, recordHash);
    }

    /// @notice Registra un accesso d'emergenza (break-glass), senza consenso del paziente.
    /// @dev Ammesso solo per il personale con EMERGENCY_ROLE e con una motivazione,
    ///      il cui testo resta off-chain; l'evento dedicato rende l'accesso facile da revisionare.
    function recordEmergencyAccess(
        address patient,
        address accessor,
        bytes32 reasonHash,
        bytes32 recordHash
    ) external onlyRole(RECORDER_ROLE) returns (uint256 entryId) {
        if (!hasRole(EMERGENCY_ROLE, accessor)) revert NotEmergencyStaff(accessor);
        if (reasonHash == bytes32(0)) revert MissingReason();
        entryId = ++totalEntries;
        emit EmergencyAccess(entryId, patient, accessor, reasonHash, recordHash);
    }
}
