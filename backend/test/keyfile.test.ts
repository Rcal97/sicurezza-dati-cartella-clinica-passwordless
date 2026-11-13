import { after, describe, it } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createBackup, readKeyFile, restoreBackup, writeKeyFile } from "../src/crypto/keyfile.js";
import { Vault } from "../src/crypto/vault.js";

const dir = mkdtempSync(join(tmpdir(), "chiavi-"));
after(() => rmSync(dir, { recursive: true }));

const vault = Vault.generate();
const passphrase = "cavallo batteria graffetta";
const testo = Buffer.from("Referto di prova");
const ctx = "doc|paz";

describe("File delle chiavi protetto da passphrase (Argon2id)", () => {
  const path = join(dir, "archivio.key");
  writeKeyFile(path, vault, passphrase);

  it("con la passphrase giusta le chiavi decifrano i referti", () => {
    assert.deepEqual(readKeyFile(path, passphrase).open(vault.seal(testo, ctx), ctx), testo);
  });

  it("con una passphrase sbagliata il file non si apre", () => {
    assert.throws(() => readKeyFile(path, "cavallo batteria graffett"), /Passphrase errata/);
  });

  it("nel file non ci sono chiavi in chiaro e i permessi sono 600", () => {
    const content = readFileSync(path, "utf8");
    assert.ok(!content.includes("PRIVATE KEY"));
    assert.ok(!content.includes(JSON.parse(vault.exportSecret().toString()).x25519));
    assert.equal(statSync(path).mode & 0o777, 0o600);
  });

  it("un file alterato viene rifiutato", () => {
    const altered = join(dir, "alterato.key");
    const file = JSON.parse(readFileSync(path, "utf8"));
    // Con parametri di Argon2id diversi la chiave derivata cambia e AES-GCM rifiuta il file.
    file.kdf.passes = 1;
    writeFileSync(altered, JSON.stringify(file));
    assert.throws(() => readKeyFile(altered, passphrase));
  });

  it("un file esistente non viene sovrascritto", () => {
    assert.throws(() => writeKeyFile(path, Vault.generate(), passphrase));
  });

  it("una passphrase troppo corta non è accettata", () => {
    assert.throws(() => writeKeyFile(join(dir, "corta.key"), vault, "breve"), /almeno 12/);
  });
});

describe("Backup delle chiavi con lo schema a soglia di Shamir (3 su 5)", async () => {
  const { backup, shares } = await createBackup(vault);

  it("produce 5 quote", () => {
    assert.equal(shares.length, 5);
    assert.equal(backup.threshold, 3);
  });

  it("tre quote qualsiasi ricostruiscono le chiavi", async () => {
    for (const trio of [[0, 1, 2], [0, 2, 4], [1, 3, 4], [4, 2, 0]]) {
      const restored = await restoreBackup(backup, trio.map((i) => shares[i]!));
      assert.equal(restored.fingerprint(), vault.fingerprint());
      assert.deepEqual(restored.open(vault.seal(testo, ctx), ctx), testo);
    }
  });

  it("due quote non bastano", async () => {
    await assert.rejects(restoreBackup(backup, [shares[0]!, shares[3]!]), /almeno 3/);
  });

  it("due quote non bastano nemmeno aggirando il controllo sul numero", async () => {
    // Con 2 quote Shamir restituisce un valore senza relazione con la chiave: AES-GCM lo rifiuta.
    await assert.rejects(restoreBackup({ ...backup, threshold: 2 }, [shares[0]!, shares[3]!]), /Quote non valide/);
  });

  it("una quota alterata viene scoperta", async () => {
    const altered = shares[1]!.slice(0, -2) + (shares[1]!.endsWith("00") ? "01" : "00");
    await assert.rejects(restoreBackup(backup, [shares[0]!, altered, shares[2]!]), /Quote non valide/);
  });

  it("le quote di un altro backup non funzionano", async () => {
    const other = await createBackup(Vault.generate());
    await assert.rejects(restoreBackup(backup, other.shares.slice(0, 3)), /Quote non valide/);
  });

  it("nel backup e nelle quote non ci sono chiavi in chiaro", () => {
    const secret = JSON.parse(vault.exportSecret().toString());
    const all = JSON.stringify(backup) + shares.join("");
    assert.ok(!all.includes(secret.mlkem) && !all.includes(secret.x25519));
  });
});
