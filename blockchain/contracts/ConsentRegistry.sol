// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";

/// @title Registro dei consensi
/// @notice Il paziente concede e revoca l'accesso ai propri dati.
contract ConsentRegistry is Ownable, Pausable {
    // paziente => destinatario => scadenza (timestamp); 0 = nessun consenso
    mapping(address patient => mapping(address grantee => uint64 expiresAt)) private _consents;

    event ConsentGranted(address indexed patient, address indexed grantee, uint64 expiresAt);
    event ConsentRevoked(address indexed patient, address indexed grantee);

    error InvalidGrantee();
    error InvalidExpiry();

    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice Concede il consenso al destinatario fino alla scadenza indicata.
    function grantConsent(address grantee, uint64 expiresAt) external whenNotPaused {
        if (grantee == address(0) || grantee == msg.sender) revert InvalidGrantee();
        if (expiresAt <= block.timestamp) revert InvalidExpiry();
        _consents[msg.sender][grantee] = expiresAt;
        emit ConsentGranted(msg.sender, grantee, expiresAt);
    }

    /// @notice Revoca il consenso. Sempre possibile, anche con il contratto in pausa.
    function revokeConsent(address grantee) external {
        delete _consents[msg.sender][grantee];
        emit ConsentRevoked(msg.sender, grantee);
    }

    /// @notice Vero se il consenso esiste e non è scaduto.
    function isConsentValid(address patient, address grantee) external view returns (bool) {
        return _consents[patient][grantee] > block.timestamp;
    }

    /// @notice Emergency Stop: blocca le nuove concessioni.
    function pause() external onlyOwner {
        _pause();
    }

    function unpause() external onlyOwner {
        _unpause();
    }
}
