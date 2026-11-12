// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title Registro dei consensi
/// @notice Il paziente concede e revoca l'accesso ai propri dati, separatamente per ogni finalità.
/// @dev L'indirizzo del paziente è uno pseudonimo dedicato a questo registro: il legame con
///      la persona reale è conservato solo off-chain e può essere cancellato.
contract ConsentRegistry is Ownable, Pausable {
    /// @notice Finalità del trattamento: un consenso vale solo per la finalità indicata.
    enum Purpose {
        Care,
        Research,
        Administration
    }

    /// @notice Durata massima di un consenso: oltre va rinnovato.
    uint64 public constant MAX_DURATION = 365 days;

    // paziente => destinatario => finalità => scadenza (timestamp); 0 = nessun consenso
    mapping(address patient => mapping(address grantee => mapping(Purpose => uint64 expiresAt)))
        private _consents;

    event ConsentGranted(
        address indexed patient,
        address indexed grantee,
        Purpose indexed purpose,
        uint64 expiresAt
    );
    event ConsentRevoked(address indexed patient, address indexed grantee, Purpose indexed purpose);

    error InvalidGrantee();
    error InvalidExpiry();

    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice Concede il consenso al destinatario, per una finalità, fino alla scadenza indicata.
    function grantConsent(address grantee, Purpose purpose, uint64 expiresAt) external whenNotPaused {
        if (grantee == address(0) || grantee == msg.sender) revert InvalidGrantee();
        if (expiresAt <= block.timestamp || expiresAt > block.timestamp + MAX_DURATION) {
            revert InvalidExpiry();
        }
        _consents[msg.sender][grantee][purpose] = expiresAt;
        emit ConsentGranted(msg.sender, grantee, purpose, expiresAt);
    }

    /// @notice Revoca il consenso per una finalità. Sempre possibile, anche con il contratto in pausa.
    function revokeConsent(address grantee, Purpose purpose) external {
        delete _consents[msg.sender][grantee][purpose];
        emit ConsentRevoked(msg.sender, grantee, purpose);
    }

    /// @notice Vero se il consenso per quella finalità esiste e non è scaduto.
    function isConsentValid(
        address patient,
        address grantee,
        Purpose purpose
    ) external view returns (bool) {
        return _consents[patient][grantee][purpose] > block.timestamp;
    }

    /// @notice Emergency Stop: blocca le nuove concessioni.
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}
