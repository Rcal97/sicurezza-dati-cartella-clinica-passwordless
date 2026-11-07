import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Il frontend gira su http://localhost:5173, che è l'origin atteso dal backend per WebAuthn.
// Le chiamate alle API passano dal proxy di Vite: per il browser frontend e backend hanno
// lo stesso origin, quindi il cookie di sessione SameSite=Strict viene inviato normalmente.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      "/webauthn": "http://127.0.0.1:3000",
      "/session": "http://127.0.0.1:3000",
    },
  },
});
