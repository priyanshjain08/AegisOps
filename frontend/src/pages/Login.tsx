import { FormEvent, useState } from "react"; import { useAuth } from "../contexts/Auth";
export default function Login() {
  const { login, register } = useAuth(); const [mode, setMode] = useState<"login" | "register">("login");
  const [f, setF] = useState({ email: "", password: "", full_name: "", organization_name: "" }); const [err, setErr] = useState<string | null>(null); const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => { e.preventDefault(); setErr(null);
    if (!/^\S+@\S+\.\S+$/.test(f.email)) return setErr("Enter a valid email address");
    if (mode === "register" && f.password.length < 12) return setErr("Password must be at least 12 characters");
    setBusy(true); try { mode === "login" ? await login(f.email, f.password) : await register(f); } catch (x: any) { setErr(x.message); } finally { setBusy(false); } };
  const set = (k: string) => (e: any) => setF({ ...f, [k]: e.target.value });
  return (<div className="min-h-screen grid place-items-center p-4"><form onSubmit={submit} className="card w-full max-w-sm space-y-3" noValidate>
    <h1 className="text-xl font-semibold text-accent">AegisOps</h1><p className="text-sm text-slate-400">{mode === "login" ? "Sign in to your organization" : "Create an organization"}</p>
    {mode === "register" && <><label className="block text-sm">Organization<input className="input" value={f.organization_name} onChange={set("organization_name")} required /></label>
      <label className="block text-sm">Full name<input className="input" value={f.full_name} onChange={set("full_name")} /></label></>}
    <label className="block text-sm">Email<input className="input" type="email" value={f.email} onChange={set("email")} required /></label>
    <label className="block text-sm">Password<input className="input" type="password" value={f.password} onChange={set("password")} required /></label>
    {err && <div role="alert" className="text-red-300 text-sm">{err}</div>}
    <button className="btn btn-primary w-full" disabled={busy}>{busy ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}</button>
    <button type="button" className="text-xs text-slate-400 underline" onClick={() => setMode(mode === "login" ? "register" : "login")}>{mode === "login" ? "Create a new organization" : "I already have an account"}</button>
  </form></div>);
}
