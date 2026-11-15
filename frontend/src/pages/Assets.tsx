import { useState } from "react"; import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/api"; import { can, useAuth } from "../contexts/Auth"; import { Loading, ErrorBox, Empty, Table, Sim, Badge } from "../components/ui";
const TYPES = ["server", "workstation", "laptop", "network_device", "cloud_resource", "application", "other"];
export default function Assets() {
  const { me } = useAuth(); const qc = useQueryClient(); const [q, setQ] = useState(""); const [f, setF] = useState({ name: "", hostname: "", ip_address: "", asset_type: "server", criticality: "medium" }); const [risk, setRisk] = useState<any>(null);
  const list = useQuery({ queryKey: ["assets", q], queryFn: () => api(`/api/assets${q ? `?q=${encodeURIComponent(q)}` : ""}`) });
  const create = useMutation({ mutationFn: () => api("/api/assets", { method: "POST", json: { ...f, hostname: f.hostname || null, ip_address: f.ip_address || null } }), onSuccess: () => { setF({ ...f, name: "", hostname: "", ip_address: "" }); qc.invalidateQueries({ queryKey: ["assets"] }); } });
  const del = useMutation({ mutationFn: (id: string) => api(`/api/assets/${id}`, { method: "DELETE" }), onSuccess: () => qc.invalidateQueries({ queryKey: ["assets"] }) });
  const admin = can(me?.role, "security_admin");
  return (<div className="space-y-4"><h1 className="text-xl font-semibold">Assets</h1><p className="text-xs text-slate-400">"No data source" means no logs have been linked; assets are not monitored in real time.</p>
    {admin && <form className="card grid md:grid-cols-6 gap-2" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
      <input className="input" placeholder="Name" required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /><input className="input" placeholder="Hostname" value={f.hostname} onChange={(e) => setF({ ...f, hostname: e.target.value })} />
      <input className="input" placeholder="IP" value={f.ip_address} onChange={(e) => setF({ ...f, ip_address: e.target.value })} />
      <select className="input" value={f.asset_type} onChange={(e) => setF({ ...f, asset_type: e.target.value })}>{TYPES.map((t) => <option key={t}>{t}</option>)}</select>
      <select className="input" value={f.criticality} onChange={(e) => setF({ ...f, criticality: e.target.value })}>{["low", "medium", "high", "critical"].map((t) => <option key={t}>{t}</option>)}</select><button className="btn btn-primary" disabled={create.isPending}>Add asset</button></form>}
    {(create.error || del.error) && <ErrorBox error={create.error || del.error} />}
    <input className="input max-w-xs" placeholder="Search assets" value={q} onChange={(e) => setQ(e.target.value)} />
    {list.isLoading ? <Loading /> : list.error ? <ErrorBox error={list.error} /> : list.data.items.length === 0 ? <Empty text="No assets registered." /> :
      <Table head={["Name", "Hostname", "IP", "Type", "Criticality", "Monitoring", ""]}>{list.data.items.map((a: any) => <tr key={a.id}><td>{a.name}<Sim v={a.is_simulated} /></td><td>{a.hostname}</td><td>{a.ip_address}</td><td>{a.asset_type}</td><td>{a.criticality}</td><td><Badge>{a.monitoring_status}</Badge></td>
        <td className="space-x-1"><button className="btn" onClick={async () => setRisk(await api(`/api/assets/${a.id}/risk`))}>Risk</button>{admin && <button className="btn" onClick={() => confirm(`Delete ${a.name}?`) && del.mutate(a.id)}>Delete</button>}</td></tr>)}</Table>}
    {risk && <div className="card text-sm">Risk for {risk.asset.name}: {risk.alerts_open} open / {risk.alerts_total} total alerts, max open score {risk.max_open_score}. <span className="text-slate-500">{risk.note}</span></div>}
  </div>);
}
