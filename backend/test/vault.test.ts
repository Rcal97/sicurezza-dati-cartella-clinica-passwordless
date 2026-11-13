import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Vault, type SealedDocument } from "../src/crypto/vault.js";

const vault = Vault.generate();
const testo = Buffer.from("Emocromo: valori nella norma.");
const ctx = "doc-1|paz.rossi";

// Modifica un byte di un campo in base64, per simulare un'alterazione nel database.
function flip(value: string): string {
  const b = Buffer.from(value, "base64");
  b[0]! ^= 0x01;
  return b.toString("base64");
}

describe("Cifratura dei referti (AES-256-GCM + ML-KEM-768/X25519)", () => {
  it("cifra e decifra un documento", () => {
    const sealed = vault.seal(testo, ctx);
    assert.deepEqual(vault.open(sealed, ctx), testo);
  });

  it("nel documento cifrato non compare il testo in chiaro", () => {
    const sealed = vault.seal(testo, ctx);
    assert.ok(!JSON.stringify(sealed).includes("Emocromo"));
    assert.ok(!Buffer.from(sealed.ciphertext, "base64").includes(Buffer.from("Emocromo")));
  });

  it("lo stesso documento cifrato due volte dà risultati diversi", () => {
    const a = vault.seal(testo, ctx);
    const b = vault.seal(testo, ctx);
    assert.notEqual(a.ciphertext, b.ciphertext);
    assert.notEqual(a.kemCiphertext, b.kemCiphertext);
  });

  it("le dimensioni corrispondono a ML-KEM-768 e X25519", () => {
    const sealed = vault.seal(testo, ctx);
    assert.equal(Buffer.from(sealed.kemCiphertext, "base64").length, 1088);
    assert.equal(Buffer.from(sealed.ecCiphertext, "base64").length, 32);
  });

  for (const field of ["ciphertext", "tag", "iv", "wrappedKey", "kemCiphertext", "ecCiphertext"] as const) {
    it(`un'alterazione di ${field} viene scoperta`, () => {
      const sealed: SealedDocument = { ...vault.seal(testo, ctx) };
      sealed[field] = flip(sealed[field]);
      assert.throws(() => vault.open(sealed, ctx));
    });
  }

  it("un documento spostato su un altro paziente non si decifra", () => {
    const sealed = vault.seal(testo, ctx);
    assert.throws(() => vault.open(sealed, "doc-1|paz.verdi"));
  });

  it("le chiavi di un altro archivio non decifrano il documento", () => {
    const sealed = vault.seal(testo, ctx);
    assert.throws(() => Vault.generate().open(sealed, ctx));
  });

  it("basta che una sola delle due chiavi private sia sbagliata perché la decifratura fallisca", () => {
    const dir = mkdtempSync(join(tmpdir(), "vault-"));
    try {
      const other = Vault.generate();
      vault.save(join(dir, "a.pem"));
      other.save(join(dir, "b.pem"));
      const [mlkemA, x25519A] = readFileSync(join(dir, "a.pem"), "utf8").split(/(?<=-----END PRIVATE KEY-----\n)/);
      const [mlkemB, x25519B] = readFileSync(join(dir, "b.pem"), "utf8").split(/(?<=-----END PRIVATE KEY-----\n)/);
      // ML-KEM giusta, X25519 sbagliata, e viceversa.
      writeFileSync(join(dir, "misto1.pem"), mlkemA! + x25519B!);
      writeFileSync(join(dir, "misto2.pem"), mlkemB! + x25519A!);
      // I file misti sono validi: il fallimento arriva solo alla decifratura.
      const misto1 = Vault.load(join(dir, "misto1.pem"));
      const misto2 = Vault.load(join(dir, "misto2.pem"));
      const sealed = vault.seal(testo, ctx);
      assert.throws(() => misto1.open(sealed, ctx));
      assert.throws(() => misto2.open(sealed, ctx));
    } finally {
      rmSync(dir, { recursive: true });
    }
  });

  it("le chiavi salvate su file funzionano dopo il caricamento e il file è privato", () => {
    const dir = mkdtempSync(join(tmpdir(), "vault-"));
    try {
      const path = join(dir, "chiavi.pem");
      vault.save(path);
      assert.equal(statSync(path).mode & 0o777, 0o600);
      assert.deepEqual(Vault.load(path).open(vault.seal(testo, ctx), ctx), testo);
      // Il file esistente non viene sovrascritto.
      assert.throws(() => Vault.generate().save(path));
    } finally {
      rmSync(dir, { recursive: true });
    }
  });
});
