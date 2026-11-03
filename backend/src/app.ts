import express from "express";
import { authRouter } from "./routes/authenticate.js";
import { sessionRouter } from "./routes/session.js";
import { webauthnRouter } from "./routes/webauthn.js";

// L'app è separata dall'avvio del server, così i test possono usarla direttamente.
export const app = express();

app.disable("x-powered-by");
app.use(express.json({ limit: "100kb" }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use("/webauthn", webauthnRouter);
app.use("/webauthn", authRouter);
app.use("/session", sessionRouter);
