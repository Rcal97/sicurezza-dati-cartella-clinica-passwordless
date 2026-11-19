// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {ConsentRegistry} from "./ConsentRegistry.sol";

/// @title Registro di audit
/// @notice Registra, in sola aggiunta, ogni accesso a una cartella clinica, senza dati personali.
/// @dev Gli accessi ordinari si riferiscono all'ancora del consenso; quelli d'emergenza
///      all'ancora del medico (HMAC del suo identificativo, calcolato off-chain con la chiave
///      della struttura). I dettagli restano off-chain, cifrati: qui c'è solo la loro impronta.
///      L'amministratore assegna il ruolo RECORDER e abilita il personale d'emergenza. Il suo
///      ruolo segue le regole di AccessControlDefaultAdminRules: passaggio di consegne in due
///      fasi e con un ritardo, visibile sulla catena prima che abbia effetto.
contract AuditLog is AccessControlDefaultAdminRules {
    bytes32 public constant RECORDER_ROLE = keccak256("RECORDER_ROLE");

    /// @notice Attesa minima prima che un nuovo amministratore possa subentrare.
    uint48 public constant ADMIN_TRANSFER_DELAY = 2 days;

    enum Outcome {
        Denied,
        Granted
    }

    ConsentRegistry public immutable consentRegistry;
    uint256 public totalEntries;

    // ancora del medico => abilitato agli accessi d'emergenza
    mapping(bytes32 staffId => bool) private _emergencyStaff;

    event AccessRecorded(uint256 indexed entryId, bytes32 indexed consentId, Outcome outcome, bytes32 recordHash);

    event EmergencyAccess(uint256 indexed entryId, bytes32 indexed staffId, bytes32 reasonHash, bytes32 recordHash);

    event EmergencyStaffChanged(bytes32 indexed staffId, bool enabled);

    error ConsentNotValid();
    error NotEmergencyStaff(bytes32 staffId);
    error MissingReason();
    error InvalidStaffId();

    constructor(address admin, ConsentRegistry registry) AccessControlDefaultAdminRules(ADMIN_TRANSFER_DELAY, admin) {
        consentRegistry = registry;
    }

    /// @notice Abilita o disabilita un medico agli accessi d'emergenza. Solo l'amministratore.
    function setEmergencyStaff(bytes32 staffId, bool enabled) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (staffId == bytes32(0)) revert InvalidStaffId();
        _emergencyStaff[staffId] = enabled;
        emit EmergencyStaffChanged(staffId, enabled);
    }

    function isEmergencyStaff(bytes32 staffId) external view returns (bool) {
        return _emergencyStaff[staffId];
    }

    /// @notice Registra un accesso ordinario. Solo il backend (RECORDER_ROLE).
    /// @param consentId ancora del consenso richiesto (paziente, medico e finalità)
    /// @param recordHash hash dei dettagli dell'accesso, conservati off-chain
    function recordAccess(
        bytes32 consentId,
        Outcome outcome,
        bytes32 recordHash
    ) external onlyRole(RECORDER_ROLE) returns (uint256 entryId) {
        if (outcome == Outcome.Granted && !consentRegistry.isConsentValid(consentId)) {
            revert ConsentNotValid();
        }
        entryId = ++totalEntries;
        emit AccessRecorded(entryId, consentId, outcome, recordHash);
    }

    /// @notice Registra un accesso d'emergenza (break-glass), senza consenso del paziente.
    /// @dev Ammesso solo per il personale abilitato e con una motivazione, il cui testo
    ///      resta off-chain; l'evento dedicato rende l'accesso facile da revisionare.
    function recordEmergencyAccess(
        bytes32 staffId,
        bytes32 reasonHash,
        bytes32 recordHash
    ) external onlyRole(RECORDER_ROLE) returns (uint256 entryId) {
        if (!_emergencyStaff[staffId]) revert NotEmergencyStaff(staffId);
        if (reasonHash == bytes32(0)) revert MissingReason();
        entryId = ++totalEntries;
        emit EmergencyAccess(entryId, staffId, reasonHash, recordHash);
    }
}
