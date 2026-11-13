import { mkdirSync, writeFileSync } from "node:fs";
import { network } from "hardhat";

// Misura del gas consumato da ogni operazione dei contratti, sulla rete di prova di Hardhat.
// Risultato: analisi/dati/gas.csv (una riga per transazione misurata).
// Uso: npx hardhat run scripts/gas.ts
const { ethers } = await network.create();
const [admin, backend, ...others] = await ethers.getSigners();
const rows: string[] = ["operazione,variante,indice,gas"];
const record = (op: string, variant: string, i: number, gas: bigint) => rows.push(`${op},${variant},${i},${gas}`);
const gasOf = async (tx: { wait(): Promise<{ gasUsed: bigint } | null> }) => (await tx.wait())!.gasUsed;

// Pubblicazione
const registry = await ethers.deployContract("ConsentRegistry", [admin.address]);
record("deploy", "ConsentRegistry", 0, (await registry.deploymentTransaction()!.wait())!.gasUsed);
const audit = await ethers.deployContract("AuditLog", [admin.address, await registry.getAddress()]);
record("deploy", "AuditLog", 0, (await audit.deploymentTransaction()!.wait())!.gasUsed);
record("ruoli", "grantRole RECORDER", 0, await gasOf(await audit.grantRole(await audit.RECORDER_ROLE(), backend.address)));
record("ruoli", "grantRole PAUSER", 0, await gasOf(await registry.grantRole(await registry.PAUSER_ROLE(), admin.address)));

const now = async () => (await ethers.provider.getBlock("latest"))!.timestamp;
const CARE = 0;
const RESEARCH = 1;
const doctor = others[0]!;
const erDoctor = others[1]!;
record("ruoli", "grantRole EMERGENCY", 0, await gasOf(await audit.grantRole(await audit.EMERGENCY_ROLE(), erDoctor.address)));

// Molti pazienti diversi: il costo di ogni operazione non deve crescere con il numero
// di pazienti o di voci già registrate (nessun ciclo su dati non limitati).
const PATIENTS = 150;
const hash = ethers.id("dettagli");
for (let i = 0; i < PATIENTS; i++) {
  const patient = ethers.Wallet.createRandom().connect(ethers.provider);
  await (await admin.sendTransaction({ to: patient.address, value: ethers.parseEther("1") })).wait();
  const p = registry.connect(patient);

  record("grantConsent", "prima concessione", i, await gasOf(await p.grantConsent(doctor.address, CARE, (await now()) + 86400)));
  record("grantConsent", "rinnovo (stessa finalità)", i, await gasOf(await p.grantConsent(doctor.address, CARE, (await now()) + 2 * 86400)));
  record("grantConsent", "seconda finalità", i, await gasOf(await p.grantConsent(doctor.address, RESEARCH, (await now()) + 86400)));

  const a = audit.connect(backend);
  record("recordAccess", "concesso", i, await gasOf(await a.recordAccess(patient.address, doctor.address, CARE, 1, hash)));
  record("recordAccess", "negato", i, await gasOf(await a.recordAccess(patient.address, others[2]!.address, CARE, 0, hash)));
  record("recordEmergencyAccess", "d'emergenza", i, await gasOf(await a.recordEmergencyAccess(patient.address, erDoctor.address, hash, hash)));

  record("revokeConsent", "revoca", i, await gasOf(await p.revokeConsent(doctor.address, RESEARCH)));
}

const out = new URL("../../analisi/dati/gas.csv", import.meta.url);
mkdirSync(new URL(".", out), { recursive: true });
writeFileSync(out, rows.join("\n") + "\n");
console.log(`${rows.length - 1} misure scritte in ${out.pathname}`);
