import type { Request, Response } from "express";
import { getAddress } from "ethers";
import type { Ledger } from "../models/ledger.js";
import type { Store } from "../models/store.js";

// Informazioni che servono al frontend, tutte non riservate: il proprio profilo (senza il
// segreto delle ancore), l'elenco dei medici e i dati della rete su cui firmare i consensi.
export function directoryController(store: Store, ledger: Ledger) {
  return {
    async profile(_req: Request, res: Response): Promise<void> {
      const username: string = res.locals.username;
      const profile = await store.getProfile(username);
      res.json({
        username,
        role: profile?.role ?? null,
        // Indirizzo nella forma con il controllo delle maiuscole (EIP-55), come lo mostrano i wallet.
        address: profile?.address ? getAddress(profile.address) : null,
      });
    },

    async doctors(_req: Request, res: Response): Promise<void> {
      res.json(await store.listDoctors());
    },

    chain(_req: Request, res: Response): void {
      res.json(ledger.chain);
    },
  };
}
