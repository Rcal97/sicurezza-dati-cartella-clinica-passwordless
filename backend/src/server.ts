import { createApp } from "./app.js";
import { mongoUrl } from "./config.js";
import { MongoStore } from "./models/mongoStore.js";

const PORT = Number(process.env.PORT ?? 3000);

const store = await MongoStore.connect(mongoUrl());
const server = createApp(store).listen(PORT, "127.0.0.1", () => {
  console.log(`Backend in ascolto su http://localhost:${PORT}`);
});

// Chiusura ordinata: termina le richieste in corso e la connessione al database.
for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, () => {
    server.close(() => void store.close().then(() => process.exit(0)));
  });
}
