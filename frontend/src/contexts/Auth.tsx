import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { api, setTokens, clearTokens, tryRestoreSession } from "../services/api";
export type Me = { id: string; email: string; full_name: string; role: string; organization: { id: string; name: string } };
const Ctx = createContext<{ me: Me | null; loading: boolean; login: (e: string, p: string) => Promise<void>; register: (b: any) => Promise<void>; logout: () => void } | null>(null);
export const useAuth = () => useContext(Ctx)!;
export const RANK: Record<string, number> = { viewer: 1, analyst: 2, security_admin: 3, owner: 4 };
export const can = (role: string | undefined, min: string) => (RANK[role ?? ""] ?? 0) >= RANK[min];

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null); const [loading, setLoading] = useState(true);
  const load = async () => setMe(await api<Me>("/api/auth/me"));
  useEffect(() => { (async () => { try { if (await tryRestoreSession()) await load(); } catch {} setLoading(false); })(); }, []);
  const take = async (d: any) => { setTokens(d.access_token, d.refresh_token); await load(); };
  return <Ctx.Provider value={{ me, loading,
    login: async (email, password) => take(await api("/api/auth/login", { method: "POST", json: { email, password } })),
    register: async (b) => take(await api("/api/auth/register", { method: "POST", json: b })),
    logout: () => { const rt = sessionStorage.getItem("rt"); api("/api/auth/logout", { method: "POST", json: { refresh_token: rt } }).catch(() => {}); clearTokens(); setMe(null); } }}>{children}</Ctx.Provider>;
}
