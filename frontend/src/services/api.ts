// Tokens: access token in memory + refresh token in sessionStorage (see SECURITY.md for the trade-off).
let access: string | null = null;
export const setTokens = (a: string, r: string) => { access = a; sessionStorage.setItem("rt", r); };
export const clearTokens = () => { access = null; sessionStorage.removeItem("rt"); };
export class ApiError extends Error { constructor(public status: number, message: string) { super(message); } }

async function refresh(): Promise<boolean> {
  const rt = sessionStorage.getItem("rt"); if (!rt) return false;
  const r = await fetch("/api/auth/refresh", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ refresh_token: rt }) });
  if (!r.ok) { clearTokens(); return false; }
  const d = await r.json(); setTokens(d.access_token, d.refresh_token); return true;
}

export async function api<T = any>(path: string, opts: RequestInit & { json?: unknown; raw?: boolean } = {}, retry = true): Promise<T> {
  const headers: Record<string, string> = { ...(opts.headers as any) };
  if (access) headers.Authorization = `Bearer ${access}`;
  if (opts.json !== undefined) { headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(opts.json); }
  const res = await fetch(path, { ...opts, headers });
  if (res.status === 401 && retry && (await refresh())) return api<T>(path, opts, false);
  if (!res.ok) {
    let msg = res.statusText; try { const b = await res.json(); msg = typeof b.detail === "string" ? b.detail : JSON.stringify(b.detail); } catch {}
    throw new ApiError(res.status, msg);
  }
  if (opts.raw) return (await res.blob()) as any;
  return res.status === 204 ? (undefined as T) : res.json();
}
export const tryRestoreSession = refresh;
