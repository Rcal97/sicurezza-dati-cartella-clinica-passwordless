import { app } from "./app.js";

const PORT = Number(process.env.PORT ?? 3000);

app.listen(PORT, "127.0.0.1", () => {
  console.log(`Backend in ascolto su http://localhost:${PORT}`);
});
