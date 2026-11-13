// Chiamate al backend. Il browser allega da solo il cookie di sessione (stesso origin).

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
  const res = await fetch(path, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(res.status, data.error ?? `Errore ${res.status}`);
  return data as T;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),

  // Utente della sessione corrente, oppure null se non c'è una sessione valida.
  async me(): Promise<string | null> {
    try {
      return (await request<{ username: string }>("GET", "/session/me")).username;
    } catch {
      return null;
    }
  },
};
