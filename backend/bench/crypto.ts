import { argon2Sync, createCipheriv, decapsulate, encapsulate, generateKeyPairSync, hkdfSync, randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { cpus, platform, release, totalmem } from "node:os";
import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from "@simplewebauthn/server";
import { isoBase64URL } from "@simplewebauthn/server/helpers";
import { config } from "../src/config.js";
import { Vault } from "../src/crypto/vault.js";
import { SoftAuthenticator } from "../test/softAuthenticator.js";

// Misure delle operazioni crittografiche del progetto, con il codice reale.
// Risultati in analisi/dati/: firme.csv, cifratura.csv, componenti.csv, argon2.csv.
// Uso: npm run bench:crypto
const OUT = new URL("../../analisi/dati/", import.meta.url);
mkdirSync(OUT, { recursive: true });
const ms = (start: bigint) => Number(process.hrtime.bigint() - start) / 1e6;
const write = (name: string, header: string, rows: string[]) => {
  writeFileSync(new URL(name, OUT), [header, ...rows].join("\n") + "\n");
  console.log(`${name}: ${rows.length} righe`);
};

// Macchina su cui sono state fatte le misure: i tempi dipendono dall'hardware.
writeFileSync(
  new URL("ambiente.json", OUT),
  JSON.stringify(
    {
      data: new Date().toISOString(),
      node: process.version,
      openssl: process.versions.openssl,
      sistema: `${platform()} ${release()}`,
      cpu: cpus()[0]?.model,
      core: cpus().length,
      memoria_gib: Math.round(totalmem() / 2 ** 30),
    },
    null,
    2,
  ) + "\n",
);

// 1. Firme WebAuthn: ES256 (classica) e ML-DSA-44 (post-quantistica).
const REPS = 300;
const firme: string[] = [];
for (const algorithm of ["ES256", "ML-DSA-44"] as const) {
  const auth = new SoftAuthenticator(algorithm);
  const regOptions = await generateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    userName: "misura",
    attestationType: "none",
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
  });
  const reg = await verifyRegistrationResponse({
    response: auth.register(regOptions, config.origin) as never,
    expectedChallenge: regOptions.challenge,
    expectedOrigin: config.origin,
    expectedRPID: config.rpID,
    requireUserVerification: true,
  });
  const credential = reg.registrationInfo!.credential;
  for (let i = 0; i < REPS + 20; i++) {
    const options = await generateAuthenticationOptions({ rpID: config.rpID, allowCredentials: [], userVerification: "required" });
    let t = process.hrtime.bigint();
    const response = auth.authenticate(options, config.origin);
    const signMs = ms(t);
    t = process.hrtime.bigint();
    const result = await verifyAuthenticationResponse({
      response: response as never,
      expectedChallenge: options.challenge,
      expectedOrigin: config.origin,
      expectedRPID: config.rpID,
      credential: { ...credential, counter: auth.counter - 1 },
      requireUserVerification: true,
    });
    const verifyMs = ms(t);
    if (!result.verified) throw new Error("verifica fallita");
    if (i < 20) continue; // riscaldamento
    const sigBytes = isoBase64URL.toBuffer(response.response.signature).length;
    firme.push([algorithm, i - 20, signMs.toFixed(4), verifyMs.toFixed(4), credential.publicKey.length, sigBytes, JSON.stringify(response).length].join(","));
  }
}
write("firme.csv", "algoritmo,ripetizione,firma_ms,verifica_ms,byte_chiave_pubblica,byte_firma,byte_risposta", firme);

// 2. Cifratura ibrida dei referti al variare della dimensione.
const vault = Vault.generate();
const cifratura: string[] = [];
for (const size of [256, 1024, 4096, 16384, 65536, 262144, 1048576]) {
  const plaintext = randomBytes(size);
  const reps = size >= 262144 ? 30 : 100;
  for (let i = 0; i < reps + 5; i++) {
    let t = process.hrtime.bigint();
    const sealed = vault.seal(plaintext, "doc|paz");
    const sealMs = ms(t);
    t = process.hrtime.bigint();
    vault.open(sealed, "doc|paz");
    const openMs = ms(t);
    if (i < 5) continue;
    cifratura.push([size, i - 5, sealMs.toFixed(4), openMs.toFixed(4), JSON.stringify(sealed).length].join(","));
  }
}
write("cifratura.csv", "byte_documento,ripetizione,cifra_ms,decifra_ms,byte_cifrati_json", cifratura);

// 3. Scomposizione: quanto pesa ciascun componente dello schema ibrido.
const mlkem = generateKeyPairSync("ml-kem-768");
const x25519 = generateKeyPairSync("x25519");
const componenti: string[] = [];
const measure = (name: string, fn: () => void, reps = 500) => {
  for (let i = 0; i < 50; i++) fn();
  for (let i = 0; i < reps; i++) {
    const t = process.hrtime.bigint();
    fn();
    componenti.push(`${name},${i},${(Number(process.hrtime.bigint() - t) / 1e3).toFixed(2)}`);
  }
};
const kemCt = encapsulate(mlkem.publicKey).ciphertext;
const ecCt = encapsulate(x25519.publicKey).ciphertext;
const key = randomBytes(32);
const aes = (n: number) => () => {
  const c = createCipheriv("aes-256-gcm", key, randomBytes(12));
  c.update(randomBytes(n));
  c.final();
  c.getAuthTag();
};
measure("ML-KEM-768 incapsulamento", () => encapsulate(mlkem.publicKey));
measure("ML-KEM-768 decapsulamento", () => decapsulate(mlkem.privateKey, kemCt));
measure("X25519 incapsulamento", () => encapsulate(x25519.publicKey));
measure("X25519 decapsulamento", () => decapsulate(x25519.privateKey, ecCt));
measure("HKDF-SHA256", () => hkdfSync("sha256", randomBytes(64), Buffer.alloc(0), randomBytes(55), 32));
measure("AES-256-GCM 4 KiB", aes(4096));
write("componenti.csv", "componente,ripetizione,microsecondi", componenti);

// 4. Argon2id: costo di un tentativo al variare di memoria e passate (parallelismo 4).
const argon: string[] = [];
for (const mib of [19, 32, 64, 128, 256]) {
  for (const passes of [1, 2, 3, 4]) {
    for (let i = 0; i < 7; i++) {
      const t = process.hrtime.bigint();
      argon2Sync("argon2id", { message: "passphrase di prova", nonce: randomBytes(16), parallelism: 4, tagLength: 32, memory: mib * 1024, passes });
      argon.push([mib, passes, i, ms(t).toFixed(2)].join(","));
    }
  }
}
write("argon2.csv", "memoria_mib,passate,ripetizione,ms", argon);
