import { useState } from "react"; import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"; import { Link } from "react-router-dom";
import { api } from "../services/api"; import { can, useAuth } from "../contexts/Auth"; import { Loading, ErrorBox, Empty, Table, Sev, Badge, Sim, fmt } from "../components/ui";
const STATUSES = ["new", "acknowledged", "investigating", "resolved", "false_positive"];
export default function Alerts() {
  const { me } = useAuth(); const qc = useQueryClient(); const [f, setF] = useState({ severity: "", status: "", q: "" }); const [open, setOpen] = useState<string | null>(null);
  const qs = new URLSearchParams(Object.entries(f).filter(([, v]) => v) as [string, string][]);
  const al = useQuery({ queryKey: ["alerts", f], queryFn: () => api(`/api/alerts?${qs}`) });
  const detail = useQuery({ queryKey: ["alert", open], queryFn: () => api(`/api/alerts/${open}`), enabled: !!open });
  const patch = useMutation({ mutationFn: ({ id, status }: any) => api(`/api/alerts/${id}`, { method: "PATCH", json: { status } }), onSuccess: () => qc.invalidateQueries() });
  return (<div className="space-y-4"><h1 className="text-xl font-semibold">Alerts</h1>
    <p className="text-xs text-slate-400">Alerts are heuristic detections, not confirmed attacks.</p>
    <div className="flex flex-wrap gap-2"><input className="input max-w-xs" placeholder="Search title" value={f.q} onChange={(e) => setF({ ...f, q: e.target.value })} />
      <select aria-label="Severity" className="input max-w-[10rem]" value={f.severity} onChange={(e) => setF({ ...f, severity: e.target.value })}><option value="">All severities</option>{["critical", "high", "medium", "low", "informational"].map((s) => <option key={s}>{s}</option>)}</select>
      <select aria-label="Status" className="input max-w-[10rem]" value={f.status} onChange={(e) => setF({ ...f, status: e.target.value })}><option value="">All statuses</option>{STATUSES.map((s) => <option key={s}>{s}</option>)}</select></div>
    {patch.error && <ErrorBox error={patch.error} />}
    {al.isLoading ? <Loading /> : al.error ? <ErrorBox error={al.error} /> : al.data.items.length === 0 ? <Empty text="No alerts match these filters." /> :
      <Table head={["Sev", "Title", "Category", "Score", "Status", "Incident", "Created"]}>{al.data.items.map((a: any) => <tr key={a.id}>
        <td><Sev v={a.severity} /></td><td><button className="underline text-left" onClick={() => setOpen(a.id)}>{a.title}</button><Sim v={a.is_simulated} /></td><td>{a.category}</td><td>{a.score}</td>
        <td>{can(me?.role, "analyst") ? <select aria-label="Alert status" className="input" value={a.status} onChange={(e) => patch.mutate({ id: a.id, status: e.target.value })}>{STATUSES.map((s) => <option key={s}>{s}</option>)}</select> : <Badge>{a.status}</Badge>}</td>
        <td>{a.incident_id ? <Link className="underline" to={`/incidents/${a.incident_id}`}>open</Link> : "-"}</td><td>{fmt(a.created_at)}</td></tr>)}</Table>}
    {open && <div className="card space-y-2"><div className="flex justify-between"><h3 className="font-medium">Alert details</h3><button className="btn" onClick={() => setOpen(null)}>Close</button></div>
      {detail.isLoading ? <Loading /> : detail.data && <><p className="text-sm">{detail.data.description}</p><p className="text-xs text-slate-400">Confidence {Math.round(detail.data.confidence * 100)}% · Related events: {detail.data.events.length}</p>
        <Table head={["Time", "Action", "Result", "User", "Source IP"]}>{detail.data.events.map((e: any) => <tr key={e.id}><td>{fmt(e.timestamp)}</td><td>{e.action}</td><td>{e.result}</td><td>{e.username}</td><td>{e.source_ip}</td></tr>)}</Table>
        <h4 className="text-sm">History</h4>{detail.data.history.map((h: any) => <div key={h.id} className="text-xs text-slate-400">{fmt(h.created_at)} · {h.action} {JSON.stringify(h.meta)}</div>)}</>}</div>}
  </div>);
}
