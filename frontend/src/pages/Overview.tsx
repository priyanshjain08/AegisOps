import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { api } from "../services/api"; import { can, useAuth } from "../contexts/Auth"; import { Loading, ErrorBox, Sev, Sim, fmt } from "../components/ui";
const Chart = ({ title, data, line }: { title: string; data: { key?: string; bucket?: string; count: number }[]; line?: boolean }) => (
  <div className="card"><h3 className="text-sm mb-2 text-slate-300">{title}</h3>{data.length === 0 ? <p className="text-sm text-slate-500">No data yet</p> :
    <ResponsiveContainer width="100%" height={180}>{line ? <LineChart data={data}><CartesianGrid stroke="#1f2937" /><XAxis dataKey="bucket" tickFormatter={(v) => new Date(v).getHours() + "h"} stroke="#64748b" /><YAxis stroke="#64748b" /><Tooltip /><Line dataKey="count" stroke="#22d3ee" dot={false} /></LineChart>
      : <BarChart data={data}><CartesianGrid stroke="#1f2937" /><XAxis dataKey="key" stroke="#64748b" tick={{ fontSize: 10 }} /><YAxis stroke="#64748b" allowDecimals={false} /><Tooltip /><Bar dataKey="count" fill="#22d3ee" /></BarChart>}</ResponsiveContainer>}</div>);
export default function Overview() {
  const { me } = useAuth(); const qc = useQueryClient();
  const q = useQuery({ queryKey: ["dashboard"], queryFn: () => api("/api/dashboard"), refetchInterval: 10000 }); // polling; Socket.IO push is not implemented
  const load = useMutation({ mutationFn: () => api("/api/demo/load", { method: "POST" }), onSuccess: () => qc.invalidateQueries() });
  const reset = useMutation({ mutationFn: () => api("/api/demo/reset", { method: "POST" }), onSuccess: () => qc.invalidateQueries() });
  if (q.isLoading) return <Loading />; if (q.error) return <ErrorBox error={q.error} />;
  const d = q.data; const c = d.cards;
  const cards = [["Total events", c.total_events], ["Active alerts", c.active_alerts], ["Critical alerts", c.critical_alerts], ["Open incidents", c.open_incidents], ["Assets", c.assets], ["Pending approvals", c.pending_approvals]];
  return (<div className="space-y-4">
    <div className="flex flex-wrap items-center gap-2 justify-between"><h1 className="text-xl font-semibold">Security overview</h1>
      <div className="flex gap-2">{can(me?.role, "security_admin") && <button className="btn btn-primary" onClick={() => load.mutate()} disabled={load.isPending}>Load simulated scenarios</button>}
        {can(me?.role, "owner") && <button className="btn" onClick={() => confirm("Delete all simulated data?") && reset.mutate()}>Reset demo data</button>}</div></div>
    {(load.error || reset.error) && <ErrorBox error={load.error || reset.error} />}
    {d.has_simulated_data && <div className="text-xs text-amber-300">This organization contains SIMULATED demo data.</div>}
    <div className="grid grid-cols-2 lg:grid-cols-6 gap-3">{cards.map(([l, v]) => <div key={l as string} className="card"><div className="text-2xl font-semibold">{v}</div><div className="text-xs text-slate-400">{l}</div></div>)}</div>
    <div className="grid lg:grid-cols-3 gap-3"><Chart title="Events over time" data={d.events_over_time} line /><Chart title="Alerts by severity" data={d.alerts_by_severity} /><Chart title="Incidents by status" data={d.incidents_by_status} />
      <Chart title="Detection categories" data={d.detection_categories} /><Chart title="Top source IPs" data={d.top_source_ips} /></div>
    <div className="card"><h3 className="text-sm mb-2">Latest alerts</h3>{d.recent_alerts.length === 0 ? <p className="text-sm text-slate-500">No alerts</p> : d.recent_alerts.map((a: any) => <div key={a.id} className="flex gap-2 items-center py-1 text-sm"><Sev v={a.severity} /><span>{a.title}</span><Sim v={a.is_simulated} /><span className="ml-auto text-slate-500 text-xs">{fmt(a.created_at)}</span></div>)}</div>
  </div>);
}
