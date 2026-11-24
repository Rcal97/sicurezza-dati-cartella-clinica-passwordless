import { readFileSync } from "node:fs";
import { formatEther, getAddress, parseEther } from "ethers";
import { network } from "hardhat";

// Trasferisce ETH di prova dall'amministratore al backend, che paga le transazioni di consensi
// e accessi. Il destinatario è lo stesso indirizzo usato per il deploy
// (ignition/parameters/<rete>.json): così non si rischia di sbagliarlo a mano.
// Importo predefinito 0,02 ETH; per cambiarlo: IMPORTO_ETH=0.01 npm run ricarica:sepolia
const { ethers, networkName } = await network.getOrCreate();
const file = new URL(`../ignition/parameters/${networkName}.json`, import.meta.url);
const backend = getAddress(JSON.parse(readFileSync(file, "utf8")).CartellaClinica.backend);
const importo = parseEther(process.env.IMPORTO_ETH ?? "0.02");
const [admin] = await ethers.getSigners();

console.log(`Rete: ${networkName}`);
console.log(`Da (amministratore): ${admin.address}, saldo ${formatEther(await ethers.provider.getBalance(admin.address))} ETH`);
console.log(`A  (backend):        ${backend}, invio ${formatEther(importo)} ETH`);

const tx = await admin.sendTransaction({ to: backend, value: importo });
console.log(`Transazione inviata: ${tx.hash}`);
await tx.wait();
console.log(`Confermata. Saldo del backend: ${formatEther(await ethers.provider.getBalance(backend))} ETH`);
