import { useState } from "react"; import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"; import { useParams } from "react-router-dom";
import { api } from "../services/api"; import { can, useAuth } from "../contexts/Auth"; import { Loading, ErrorBox, Sev, Badge, Table, fmt } from "../components/ui";
const KIND: Record<string, string> = { observed_event: "Observed", detection: "Detection", analyst_action: "Analyst", ai_analysis: "AI", response: "Response" };
const List = ({ items }: { items?: any[] }) => <ul className="list-disc ml-5 text-sm">{(items ?? []).map((x, i) => <li key={i}>{typeof x === "string" ? x : JSON.stringify(x)}</li>)}</ul>;
export default function IncidentDetail() {
  const { id } = useParams(); const { me } = useAuth(); const qc = useQueryClient(); const [note, setNote] = useState(""); const [ip, setIp] = useState("");
  const q = useQuery({ queryKey: ["incident", id], queryFn: () => api(`/api/incidents/${id}`) });
  const inv = () => qc.invalidateQueries({ queryKey: ["incident", id] });
  const addNote = useMutation({ mutationFn: () => api(`/api/incidents/${id}/notes`, { method: "POST", json: { body: note } }), onSuccess: () => { setNote(""); inv(); } });
  const setStatus = useMutation({ mutationFn: (status: string) => api(`/api/incidents/${id}`, { method: "PATCH", json: { status } }), onSuccess: inv });
  const analyze = useMutation({ mutationFn: () => api(`/api/investigations/${id}/analyze`, { method: "POST" }), onSuccess: inv });
  const request = useMutation({ mutationFn: () => api("/api/response-actions", { method: "POST", json: { action_type: "block_ip_simulated", params: { ip }, incident_id: id } }), onSuccess: () => { setIp(""); inv(); } });
  const download = async (fmtName: string) => { const b = await api<Blob>(`/api/reports/incidents/${id}?fmt=${fmtName}`, { raw: true }); const a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = `incident-${id}.${fmtName}`; a.click(); };
  if (q.isLoading) return <Loading />; if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data, an = d.analyses[0]?.content, canW = can(me?.role, "analyst");
  return (<div className="space-y-4">
    <div className="flex flex-wrap gap-2 items-center"><h1 className="text-xl font-semibold">{d.title}</h1><Sev v={d.severity} /><Badge>{d.status}</Badge>
      {canW && <select aria-label="Incident status" className="input max-w-[10rem]" value={d.status} onChange={(e) => setStatus.mutate(e.target.value)}>{["open", "investigating", "contained", "resolved", "closed"].map((s) => <option key={s}>{s}</option>)}</select>}
      <div className="ml-auto flex gap-2">{canW && ["pdf", "csv", "json"].map((f) => <button key={f} className="btn" onClick={() => download(f)}>Report {f.toUpperCase()}</button>)}</div></div>
    {(addNote.error || setStatus.error || analyze.error || request.error) && <ErrorBox error={addNote.error || setStatus.error || analyze.error || request.error} />}
    <p className="text-sm text-slate-400">{d.description}</p>
    <div className="card"><h3 className="text-sm mb-2">Timeline</h3>{d.timeline.map((t: any, i: number) => <div key={i} className="text-sm flex gap-2 py-0.5"><span className="text-slate-500 w-40 shrink-0">{fmt(t.at)}</span><Badge>{KIND[t.kind]}</Badge><span>{t.label}</span></div>)}</div>
    <div className="card space-y-2"><div className="flex justify-between items-center"><h3 className="text-sm">AI analysis {d.analyses.length > 0 && <span className="text-slate-500">(v{d.analyses[0].version}, {d.analyses.length} version(s) kept)</span>}</h3>{canW && <button className="btn btn-primary" disabled={analyze.isPending} onClick={() => analyze.mutate()}>{an ? "Regenerate" : "Generate analysis"}</button>}</div>
      {!an ? <p className="text-sm text-slate-500">No analysis yet.</p> : <div className="space-y-2">
        <div className="text-xs px-2 py-1 rounded bg-slate-700/50 inline-block">{an.is_llm ? `AI-generated (${an.provider})` : "Non-LLM rule-based analysis"}</div>{an.notice && <p className="text-xs text-amber-300">{an.notice}</p>}
        <p className="text-sm">{an.executive_summary}</p><h4 className="text-xs text-slate-400">What happened</h4><List items={an.what_happened} /><h4 className="text-xs text-slate-400">Why suspicious</h4><List items={an.why_suspicious} />
        <h4 className="text-xs text-slate-400">ATT&CK mapping (heuristic)</h4><List items={(an.attack_technique ?? []).map((t: any) => `${t.id} ${t.name ?? ""} - ${t.basis ?? ""}`)} />
        <p className="text-sm"><b>Confidence:</b> {an.confidence?.level} — {an.confidence?.uncertainty}</p><h4 className="text-xs text-slate-400">Investigation steps</h4><List items={an.investigation_steps} /><h4 className="text-xs text-slate-400">Missing information</h4><List items={an.missing_information} /></div>}</div>
    <div className="card"><h3 className="text-sm mb-2">Related alerts</h3><Table head={["Sev", "Title", "Status"]}>{d.alerts.map((a: any) => <tr key={a.id}><td><Sev v={a.severity} /></td><td>{a.title}</td><td>{a.status}</td></tr>)}</Table></div>
    <div className="card"><h3 className="text-sm mb-2">Response actions</h3>{d.actions.length === 0 ? <p className="text-sm text-slate-500">None. Approvals happen in the Response Center.</p> : d.actions.map((a: any) => <div key={a.id} className="text-sm">{a.action_type} {JSON.stringify(a.params)} <Badge>{a.approval_status}</Badge> <Badge>{a.execution_status}</Badge>{a.origin === "ai" && <Badge>AI-proposed</Badge>}</div>)}
      {canW && <div className="flex gap-2 mt-2"><input className="input max-w-xs" aria-label="IP to block" placeholder="Public IP to block (simulated)" value={ip} onChange={(e) => setIp(e.target.value)} /><button className="btn" disabled={!ip || request.isPending} onClick={() => request.mutate()}>Request simulated block</button></div>}</div>
    <div className="card space-y-2"><h3 className="text-sm">Investigation notes</h3>{d.notes.map((n: any) => <div key={n.id} className="text-sm border-t border-line pt-1"><span className="text-xs text-slate-500">{fmt(n.created_at)}</span> {n.body}</div>)}
      {canW && <div className="flex gap-2"><textarea className="input" aria-label="Note" value={note} onChange={(e) => setNote(e.target.value)} /><button className="btn" disabled={!note.trim() || addNote.isPending} onClick={() => addNote.mutate()}>Add note</button></div>}</div>
    <div className="card"><h3 className="text-sm mb-2">Audit history</h3>{d.audit.map((a: any) => <div key={a.id} className="text-xs text-slate-400">{fmt(a.created_at)} · {a.action}</div>)}</div>
  </div>);
}
