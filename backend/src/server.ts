import express from "express";
import { webauthnRouter } from "./routes/webauthn.js";

const app = express();
const PORT = Number(process.env.PORT ?? 3000);

app.disable("x-powered-by");
app.use(express.json({ limit: "100kb" }));

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.use("/webauthn", webauthnRouter);

app.listen(PORT, "127.0.0.1", () => {
  console.log(`Backend in ascolto su http://localhost:${PORT}`);
});
