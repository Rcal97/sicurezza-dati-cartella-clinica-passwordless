import { describe, it } from "node:test";
import assert from "node:assert/strict";
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

  it("i nuovi documenti usano la versione 2 dello schema", () => {
    assert.equal(vault.seal(testo, ctx).v, 2);
  });

  it("i documenti cifrati con la versione 1 restano leggibili", () => {
    const old = vault.seal(testo, ctx, 1);
    assert.equal(old.v, 1);
    assert.deepEqual(vault.open(old, ctx), testo);
  });

  it("cambiare la versione dichiarata nel documento fa fallire la decifratura", () => {
    const sealed = vault.seal(testo, ctx);
    assert.throws(() => vault.open({ ...sealed, v: 1 }, ctx));
    assert.throws(() => vault.open({ ...sealed, v: 3 }, ctx), /non supportata/);
  });

  it("basta che una sola delle due chiavi private sia sbagliata perché la decifratura fallisca", () => {
    const a = JSON.parse(vault.exportSecret().toString());
    const b = JSON.parse(Vault.generate().exportSecret().toString());
    // ML-KEM giusta e X25519 sbagliata, e viceversa: chiavi valide, ma non quelle giuste.
    const misto1 = Vault.fromSecret(Buffer.from(JSON.stringify({ mlkem: a.mlkem, x25519: b.x25519 })));
    const misto2 = Vault.fromSecret(Buffer.from(JSON.stringify({ mlkem: b.mlkem, x25519: a.x25519 })));
    const sealed = vault.seal(testo, ctx);
    assert.throws(() => misto1.open(sealed, ctx));
    assert.throws(() => misto2.open(sealed, ctx));
  });
});
