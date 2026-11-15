import { useRef, useState } from "react"; import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/api"; import { can, useAuth } from "../contexts/Auth"; import { Loading, ErrorBox, Empty, Table, Sev, fmt } from "../components/ui";
export default function Events() {
  const { me } = useAuth(); const qc = useQueryClient(); const [q, setQ] = useState(""); const [sev, setSev] = useState(""); const [p, setP] = useState(1); const file = useRef<HTMLInputElement>(null);
  const qs = new URLSearchParams({ p: String(p), size: "50", ...(q && { q }), ...(sev && { severity: sev }) });
  const ev = useQuery({ queryKey: ["events", q, sev, p], queryFn: () => api(`/api/events?${qs}`) });
  const jobs = useQuery({ queryKey: ["jobs"], queryFn: () => api("/api/ingestion/jobs?size=5") });
  const up = useMutation({ mutationFn: async (f: File) => { const ext = f.name.split(".").pop()!.toLowerCase(); const fmtName = ext === "jsonl" ? "jsonl" : ext === "csv" ? "csv" : "json";
      const fd = new FormData(); fd.append("file", f); return api(`/api/ingestion/upload?fmt=${fmtName}`, { method: "POST", body: fd }); }, onSuccess: () => qc.invalidateQueries() });
  return (<div className="space-y-4"><h1 className="text-xl font-semibold">Events</h1>
    {can(me?.role, "analyst") && <div className="card flex flex-wrap gap-2 items-center"><input ref={file} type="file" accept=".json,.jsonl,.csv" className="text-sm" />
      <button className="btn btn-primary" disabled={up.isPending} onClick={() => file.current?.files?.[0] ? up.mutate(file.current.files[0]) : alert("Choose a .json, .jsonl or .csv file")}>Upload logs</button>
      {up.data && <span className="text-sm">Job {up.data.status}: {up.data.accepted}/{up.data.total} accepted, {up.data.rejected} rejected</span>}{up.error && <ErrorBox error={up.error} />}</div>}
    {jobs.data?.items?.[0]?.errors?.length > 0 && <div className="card text-sm"><b>Latest job rejections</b>{jobs.data.items[0].errors.slice(0, 5).map((e: any, i: number) => <div key={i} className="text-amber-300">#{e.index ?? "-"}: {e.error}</div>)}</div>}
    <div className="flex gap-2"><input className="input max-w-xs" placeholder="Search action, user, host, IP" value={q} onChange={(e) => { setQ(e.target.value); setP(1); }} />
      <select className="input max-w-[10rem]" value={sev} onChange={(e) => { setSev(e.target.value); setP(1); }}><option value="">All severities</option>{["informational", "low", "medium", "high", "critical"].map((s) => <option key={s}>{s}</option>)}</select></div>
    {ev.isLoading ? <Loading /> : ev.error ? <ErrorBox error={ev.error} /> : ev.data.items.length === 0 ? <Empty text="No events. Upload logs or load simulated scenarios from Overview." /> :
      <><Table head={["Time", "Sev", "Category", "Action", "Result", "User", "Host", "Source IP"]}>{ev.data.items.map((e: any) => <tr key={e.id}><td>{fmt(e.timestamp)}</td><td><Sev v={e.severity} /></td><td>{e.category}</td><td>{e.action}</td><td>{e.result}</td><td>{e.username}</td><td>{e.hostname}</td><td>{e.source_ip}</td></tr>)}</Table>
      <div className="flex gap-2 items-center text-sm"><button className="btn" disabled={p === 1} onClick={() => setP(p - 1)}>Prev</button>Page {p} · {ev.data.total} events<button className="btn" disabled={p * 50 >= ev.data.total} onClick={() => setP(p + 1)}>Next</button></div></>}
  </div>);
}
