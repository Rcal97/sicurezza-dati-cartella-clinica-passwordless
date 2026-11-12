import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

// Pubblica i due contratti e assegna i ruoli.
// Account 0: amministratore (proprietario del registro, admin dell'audit).
// Account 1: backend, che riceve solo il ruolo RECORDER (privilegio minimo).
export default buildModule("CartellaClinica", (m) => {
  const admin = m.getAccount(0);
  const backend = m.getAccount(1);

  const consentRegistry = m.contract("ConsentRegistry", [admin], { from: admin });
  const auditLog = m.contract("AuditLog", [admin, consentRegistry], { from: admin });

  const recorderRole = m.staticCall(auditLog, "RECORDER_ROLE");
  m.call(auditLog, "grantRole", [recorderRole, backend], { from: admin });

  return { consentRegistry, auditLog };
});
