import { mkdirSync, writeFileSync } from "node:fs";
import { network } from "hardhat";

// Misura del gas consumato da ogni operazione dei contratti, sulla rete di prova di Hardhat.
// Risultato: analisi/dati/gas.csv (una riga per transazione misurata).
// Uso: npx hardhat run scripts/gas.ts
const { ethers } = await network.create();
const [admin, backend] = await ethers.getSigners();
const rows: string[] = ["operazione,variante,indice,gas"];
const record = (op: string, variant: string, i: number, gas: bigint) => rows.push(`${op},${variant},${i},${gas}`);
const gasOf = async (tx: { wait(): Promise<{ gasUsed: bigint } | null> }) => (await tx.wait())!.gasUsed;

// Pubblicazione
const registry = await ethers.deployContract("ConsentRegistry", [admin.address]);
record("deploy", "ConsentRegistry", 0, (await registry.deploymentTransaction()!.wait())!.gasUsed);
const audit = await ethers.deployContract("AuditLog", [admin.address, await registry.getAddress()]);
record("deploy", "AuditLog", 0, (await audit.deploymentTransaction()!.wait())!.gasUsed);
record("ruoli", "grantRole RECORDER", 0, await gasOf(await audit.grantRole(await audit.RECORDER_ROLE(), backend.address)));
record("ruoli", "grantRole REGISTRAR", 0, await gasOf(await registry.grantRole(await registry.REGISTRAR_ROLE(), backend.address)));
record("ruoli", "grantRole PAUSER", 0, await gasOf(await registry.grantRole(await registry.PAUSER_ROLE(), admin.address)));

const now = async () => (await ethers.provider.getBlock("latest"))!.timestamp;
// Le ancore sono valori opachi di 32 byte: qui bastano valori casuali.
const anchor = () => ethers.hexlify(ethers.randomBytes(32));
const erDoctor = anchor();
record("ruoli", "setEmergencyStaff", 0, await gasOf(await audit.setEmergencyStaff(erDoctor, true)));

// Molti pazienti diversi: il costo di ogni operazione non deve crescere con il numero
// di pazienti o di voci già registrate (nessun ciclo su dati non limitati).
const PATIENTS = 150;
const r = registry.connect(backend);
const a = audit.connect(backend);
for (let i = 0; i < PATIENTS; i++) {
  const care = anchor();
  const research = anchor();
  const receipt = anchor();
  const hash = anchor();

  record("grantConsent", "prima concessione", i, await gasOf(await r.grantConsent(care, (await now()) + 86400, receipt)));
  record("grantConsent", "rinnovo (stessa finalità)", i, await gasOf(await r.grantConsent(care, (await now()) + 2 * 86400, receipt)));
  record("grantConsent", "seconda finalità", i, await gasOf(await r.grantConsent(research, (await now()) + 86400, receipt)));

  record("recordAccess", "concesso", i, await gasOf(await a.recordAccess(care, 1, hash)));
  record("recordAccess", "negato", i, await gasOf(await a.recordAccess(anchor(), 0, hash)));
  record("recordEmergencyAccess", "d'emergenza", i, await gasOf(await a.recordEmergencyAccess(erDoctor, hash, hash)));

  record("revokeConsent", "revoca", i, await gasOf(await r.revokeConsent(research, receipt)));
}

const out = new URL("../../analisi/dati/gas.csv", import.meta.url);
mkdirSync(new URL(".", out), { recursive: true });
writeFileSync(out, rows.join("\n") + "\n");
console.log(`${rows.length - 1} misure scritte in ${out.pathname}`);
