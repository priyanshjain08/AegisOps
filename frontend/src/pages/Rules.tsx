import { useState } from "react"; import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/api"; import { can, useAuth } from "../contexts/Auth"; import { Loading, ErrorBox, Sev, fmt } from "../components/ui";
function Row({ r, admin }: { r: any; admin: boolean }) {
  const qc = useQueryClient(); const [txt, setTxt] = useState(JSON.stringify(r.thresholds, null, 1)); const [err, setErr] = useState<string | null>(null);
  const patch = useMutation({ mutationFn: (json: any) => api(`/api/detection-rules/${r.id}`, { method: "PATCH", json }), onSuccess: () => qc.invalidateQueries({ queryKey: ["rules"] }), onError: (e: any) => setErr(e.message) });
  const save = () => { try { setErr(null); patch.mutate({ thresholds: JSON.parse(txt) }); } catch { setErr("Thresholds must be valid JSON"); } };
  return (<div className="card space-y-2"><div className="flex flex-wrap gap-2 items-center"><b>{r.rule_key}</b><span>{r.name}</span><Sev v={r.severity} /><span className="text-xs text-slate-500">v{r.version} · last run {fmt(r.last_executed_at)}</span>
    <label className="ml-auto text-sm flex gap-2 items-center"><input type="checkbox" disabled={!admin} checked={r.enabled} onChange={(e) => patch.mutate({ enabled: e.target.checked })} />Enabled</label></div>
    <p className="text-sm text-slate-400">{r.description}</p><textarea aria-label={`Thresholds ${r.rule_key}`} className="input font-mono text-xs" rows={3} disabled={!admin} value={txt} onChange={(e) => setTxt(e.target.value)} />
    {admin && <button className="btn" onClick={save}>Save thresholds</button>}{err && <div role="alert" className="text-red-300 text-sm">{err}</div>}</div>);
}
export default function Rules() {
  const { me } = useAuth(); const qc = useQueryClient(); const admin = can(me?.role, "security_admin"); const q = useQuery({ queryKey: ["rules"], queryFn: () => api("/api/detection-rules") });
  const ev = useMutation({ mutationFn: () => api("/api/detection-rules/evaluate", { method: "POST" }), onSuccess: () => qc.invalidateQueries() });
  return (<div className="space-y-3"><div className="flex justify-between"><h1 className="text-xl font-semibold">Detection rules</h1>{admin && <button className="btn btn-primary" disabled={ev.isPending} onClick={() => ev.mutate()}>Re-evaluate historical events</button>}</div>
    {ev.data && <div className="text-sm">Evaluated {ev.data.events_evaluated} events, created {ev.data.alerts_created} new alerts.</div>}{ev.error && <ErrorBox error={ev.error} />}
    {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data.map((r: any) => <Row key={r.id} r={r} admin={admin} />)}</div>);
}
