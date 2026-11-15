import { useState } from "react"; import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../services/api"; import { can, useAuth } from "../contexts/Auth"; import { Loading, ErrorBox, Empty, Table, Badge, fmt } from "../components/ui";
export default function Response() {
  const { me } = useAuth(); const qc = useQueryClient(); const [status, setStatus] = useState(""); const admin = can(me?.role, "security_admin");
  const q = useQuery({ queryKey: ["actions", status], queryFn: () => api(`/api/response-actions${status ? `?status=${status}` : ""}`), refetchInterval: 10000 });
  const done = () => qc.invalidateQueries();
  const decide = useMutation({ mutationFn: ({ id, approve }: any) => api(`/api/approvals/${id}`, { method: "POST", json: { approve } }), onSuccess: done });
  const exec = useMutation({ mutationFn: (id: string) => api(`/api/response-actions/${id}/execute`, { method: "POST" }), onSuccess: done });
  return (<div className="space-y-4"><h1 className="text-xl font-semibold">Response center</h1><p className="text-xs text-slate-400">Every action needs human approval. IP blocks run against a simulated firewall only; no real systems are changed.</p>
    <select aria-label="Approval status" className="input max-w-[14rem]" value={status} onChange={(e) => setStatus(e.target.value)}><option value="">All</option>{["pending_approval", "approved", "rejected", "cancelled"].map((s) => <option key={s}>{s}</option>)}</select>
    {(decide.error || exec.error) && <ErrorBox error={decide.error || exec.error} />}
    {q.isLoading ? <Loading /> : q.error ? <ErrorBox error={q.error} /> : q.data.items.length === 0 ? <Empty text="No response actions." /> :
      <Table head={["Action", "Parameters (preview)", "Origin", "Approval", "Execution", "Result", "Created", ""]}>{q.data.items.map((a: any) => <tr key={a.id}><td>{a.action_type}</td><td className="font-mono text-xs">{JSON.stringify(a.params)}</td><td>{a.origin}</td><td><Badge>{a.approval_status}</Badge></td><td><Badge>{a.execution_status}</Badge></td><td className="text-xs">{a.result?.message ?? a.result?.error ?? ""}</td><td>{fmt(a.created_at)}</td>
        <td className="space-x-1">{admin && a.approval_status === "pending_approval" && <><button className="btn" onClick={() => decide.mutate({ id: a.id, approve: true })}>Approve</button><button className="btn" onClick={() => decide.mutate({ id: a.id, approve: false })}>Reject</button></>}
          {admin && a.approval_status === "approved" && a.execution_status !== "executed" && <button className="btn btn-primary" onClick={() => exec.mutate(a.id)}>Execute (simulated)</button>}</td></tr>)}</Table>}</div>);
}
