import { createInterface } from "node:readline/promises";

// Chiede una passphrase senza mostrarla sullo schermo (né salvarla nella cronologia).
export async function askHidden(question: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    // Input non interattivo (per esempio da una pipe): si legge una riga.
    const rl = createInterface({ input: stdin });
    const line = await rl.question("");
    rl.close();
    return line;
  }
  process.stdout.write(question);
  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding("utf8");
  return new Promise((resolve) => {
    let value = "";
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off("data", onData);
          process.stdout.write("\n");
          resolve(value);
          return;
        }
        if (ch === "\u0003") process.exit(130); // Ctrl+C
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1); // Backspace
        else value += ch;
      }
    };
    stdin.on("data", onData);
  });
}

// Apre il file delle chiavi chiedendo la passphrase; in caso di errore termina con un messaggio chiaro.
export async function unlockOrExit<T>(open: (passphrase: string) => T, question = "Passphrase delle chiavi: "): Promise<T> {
  try {
    return open(await askHidden(question));
  } catch (err) {
    console.error((err as Error).message);
    process.exit(1);
  }
}

// Nuova passphrase, chiesta due volte.
export async function askNewPassphrase(min: number): Promise<string> {
  for (;;) {
    const first = await askHidden(`Nuova passphrase (almeno ${min} caratteri): `);
    if (first.length < min) {
      console.error("Troppo corta.");
      continue;
    }
    if ((await askHidden("Ripeti la passphrase: ")) === first) return first;
    console.error("Le due passphrase non coincidono.");
  }
}
