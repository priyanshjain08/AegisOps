import { useState } from "react"; import { useQuery } from "@tanstack/react-query"; import { api } from "../services/api"; import { Loading, ErrorBox, Empty, Table, fmt } from "../components/ui";
export default function Audit() {
  const [p, setP] = useState(1); const [action, setAction] = useState(""); const q = useQuery({ queryKey: ["audit", p, action], queryFn: () => api(`/api/audit?p=${p}${action ? `&action=${encodeURIComponent(action)}` : ""}`) });
  return (<div className="space-y-4"><h1 className="text-xl font-semibold">Audit logs</h1><p className="text-xs text-slate-400">Read-only. Visible to Security Administrators and Owners.</p>
    <input className="input max-w-xs" placeholder="Action prefix, e.g. response." value={action} onChange={(e) => { setAction(e.target.value); setP(1); }} />
    {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data.items.length === 0 ? <Empty text="No audit entries." /> : <><Table head={["Time", "Action", "Resource", "Metadata", "Request ID"]}>{q.data.items.map((a: any) => <tr key={a.id}><td>{fmt(a.created_at)}</td><td>{a.action}</td><td>{a.resource_type} {a.resource_id?.slice(0, 8)}</td><td className="font-mono text-xs">{JSON.stringify(a.meta)}</td><td className="text-xs">{a.request_id?.slice(0, 8)}</td></tr>)}</Table>
      <div className="flex gap-2 text-sm items-center"><button className="btn" disabled={p === 1} onClick={() => setP(p - 1)}>Prev</button>Page {p}<button className="btn" disabled={p * 50 >= q.data.total} onClick={() => setP(p + 1)}>Next</button></div></>}</div>);
}
