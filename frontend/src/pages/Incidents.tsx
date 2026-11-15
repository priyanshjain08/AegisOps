import { useState } from "react"; import { useQuery } from "@tanstack/react-query"; import { Link } from "react-router-dom";
import { api } from "../services/api"; import { Loading, ErrorBox, Empty, Table, Sev, Badge, Sim, fmt } from "../components/ui";
export default function Incidents() {
  const [status, setStatus] = useState(""); const q = useQuery({ queryKey: ["incidents", status], queryFn: () => api(`/api/incidents${status ? `?status=${status}` : ""}`) });
  return (<div className="space-y-4"><h1 className="text-xl font-semibold">Incidents</h1>
    <select aria-label="Status" className="input max-w-[12rem]" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">All statuses</option>{["open", "investigating", "contained", "resolved", "closed"].map((s) => <option key={s}>{s}</option>)}</select>
    {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data.items.length === 0 ? <Empty text="No incidents yet." /> :
      <Table head={["Sev", "Title", "Status", "Created"]}>{q.data.items.map((i: any) => <tr key={i.id}><td><Sev v={i.severity} /></td><td><Link className="underline" to={`/incidents/${i.id}`}>{i.title}</Link><Sim v={i.is_simulated} /></td><td><Badge>{i.status}</Badge></td><td>{fmt(i.created_at)}</td></tr>)}</Table>}
  </div>);
}
