import { getAddress, isAddress, JsonRpcProvider, parseEther, formatEther, toQuantity } from "ethers";
import { ledgerConfig } from "../config.js";

// Solo per la blockchain locale di sviluppo. Dopo ogni riavvio del nodo la catena riparte vuota:
// questo script dà al wallet di prova del paziente gli ETH per il gas e, se serve, allinea il
// numero delle sue transazioni (nonce) a quello che il wallet ricorda.
// Uso: npm run wallet-prova -- <indirizzo> [nonce]
const [address, nonceArg] = process.argv.slice(2);
if (!address || !isAddress(address) || (nonceArg !== undefined && !/^\d+$/.test(nonceArg))) {
  console.error("Uso: npm run wallet-prova -- <indirizzo> [nonce]");
  process.exit(1);
}

const provider = new JsonRpcProvider(ledgerConfig().rpcUrl);
try {
  // Queste operazioni esistono solo sul nodo di sviluppo: su una rete vera lo script si ferma.
  const { chainId } = await provider.getNetwork();
  if (chainId !== 31337n) {
    console.error(`Rete ${chainId}: lo script funziona solo sulla blockchain locale (31337).`);
    process.exit(1);
  }
  const to = getAddress(address);
  const signer = await provider.getSigner(0);
  await (await signer.sendTransaction({ to, value: parseEther("10") })).wait();
  if (nonceArg !== undefined) await provider.send("hardhat_setNonce", [to, toQuantity(BigInt(nonceArg))]);
  const balance = formatEther(await provider.getBalance(to));
  console.log(`${to}: ${balance} ETH, nonce ${await provider.getTransactionCount(to)}`);
} finally {
  provider.destroy();
}
