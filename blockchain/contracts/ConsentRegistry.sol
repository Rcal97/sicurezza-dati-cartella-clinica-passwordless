// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {AccessControlDefaultAdminRules} from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title Registro dei consensi
/// @notice Stato dei consensi, senza alcun dato personale: ogni consenso è un'ancora opaca
///         con una scadenza; la prova, cioè la ricevuta firmata dal paziente, resta off-chain e cifrata.
/// @dev consentId = HMAC-SHA256 calcolato off-chain con la chiave della struttura sul segreto
///      del paziente, sul medico e sulla finalità. Chi legge la catena non può risalire a nessuno
///      dei tre; cancellando il segreto del paziente il legame si perde per sempre.
///      receiptHash è l'impronta della ricevuta del consenso (JSON firmato dal paziente con EIP-712).
///      Scrive solo il REGISTRAR_ROLE (il backend), dopo aver verificato la firma del paziente:
///      così sulla catena non compare né l'indirizzo del paziente né quello del medico.
///      Le scadenze usano block.timestamp: sono dell'ordine dei giorni, e lo scarto di pochi
///      secondi che chi produce il blocco può introdurre non ha effetti pratici.
///      L'amministrazione segue le regole di AccessControlDefaultAdminRules: un solo
///      amministratore, passaggio di consegne in due fasi e con un ritardo, niente rinuncia
///      immediata. La pausa spetta a un ruolo separato (PAUSER_ROLE).
contract ConsentRegistry is AccessControlDefaultAdminRules, Pausable {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant REGISTRAR_ROLE = keccak256("REGISTRAR_ROLE");

    /// @notice Attesa minima prima che un nuovo amministratore possa subentrare.
    uint48 public constant ADMIN_TRANSFER_DELAY = 2 days;

    /// @notice Durata massima di un consenso: oltre va rinnovato.
    uint64 public constant MAX_DURATION = 365 days;

    // ancora del consenso => scadenza (timestamp); 0 = nessun consenso
    mapping(bytes32 consentId => uint64 expiresAt) private _consents;

    event ConsentGranted(bytes32 indexed consentId, uint64 expiresAt, bytes32 receiptHash);
    event ConsentRevoked(bytes32 indexed consentId, bytes32 receiptHash);

    error InvalidConsentId();
    error InvalidExpiry();
    error MissingReceipt();

    constructor(address admin) AccessControlDefaultAdminRules(ADMIN_TRANSFER_DELAY, admin) {}

    /// @notice Registra un consenso fino alla scadenza indicata, con l'impronta della sua ricevuta.
    function grantConsent(
        bytes32 consentId,
        uint64 expiresAt,
        bytes32 receiptHash
    ) external onlyRole(REGISTRAR_ROLE) whenNotPaused {
        if (consentId == bytes32(0)) revert InvalidConsentId();
        if (receiptHash == bytes32(0)) revert MissingReceipt();
        if (expiresAt <= block.timestamp || expiresAt > block.timestamp + MAX_DURATION) {
            revert InvalidExpiry();
        }
        _consents[consentId] = expiresAt;
        emit ConsentGranted(consentId, expiresAt, receiptHash);
    }

    /// @notice Registra una revoca, con l'impronta della ricevuta. Sempre possibile, anche in pausa.
    function revokeConsent(bytes32 consentId, bytes32 receiptHash) external onlyRole(REGISTRAR_ROLE) {
        if (receiptHash == bytes32(0)) revert MissingReceipt();
        delete _consents[consentId];
        emit ConsentRevoked(consentId, receiptHash);
    }

    /// @notice Vero se il consenso esiste e non è scaduto.
    function isConsentValid(bytes32 consentId) external view returns (bool) {
        return _consents[consentId] > block.timestamp;
    }

    /// @notice Emergency Stop: blocca le nuove concessioni.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }
}
