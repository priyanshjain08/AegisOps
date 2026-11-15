import { useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { Activity, AlertTriangle, Server, ShieldCheck, ScrollText, Siren, Search, FileSearch, Menu, LogOut } from "lucide-react";
import { useAuth } from "./contexts/Auth";
import Login from "./pages/Login"; import Overview from "./pages/Overview"; import Events from "./pages/Events"; import Alerts from "./pages/Alerts";
import Incidents from "./pages/Incidents"; import IncidentDetail from "./pages/IncidentDetail"; import Assets from "./pages/Assets"; import Rules from "./pages/Rules";
import Response from "./pages/Response"; import Audit from "./pages/Audit"; import { Loading } from "./components/ui";

const NAV = [["/", "Overview", Activity], ["/events", "Events", Search], ["/alerts", "Alerts", AlertTriangle], ["/incidents", "Incidents", Siren],
  ["/assets", "Assets", Server], ["/rules", "Detection Rules", ShieldCheck], ["/response", "Response Center", FileSearch], ["/audit", "Audit Logs", ScrollText]] as const;

export default function App() {
  const { me, loading, logout } = useAuth(); const [open, setOpen] = useState(false);
  if (loading) return <div className="p-8"><Loading /></div>;
  if (!me) return <Routes><Route path="*" element={<Login />} /></Routes>;
  return (
    <div className="min-h-screen md:flex">
      <header className="md:hidden flex items-center justify-between p-3 border-b border-line"><b>AegisOps</b><button aria-label="Toggle menu" onClick={() => setOpen(!open)}><Menu /></button></header>
      <aside className={`${open ? "block" : "hidden"} md:block w-full md:w-56 shrink-0 border-r border-line bg-panel p-3 space-y-1`}>
        <div className="hidden md:block font-bold text-accent px-2 pb-2">AegisOps</div>
        {NAV.map(([to, label, Icon]) => <NavLink key={to} to={to} end={to === "/"} onClick={() => setOpen(false)}
          className={({ isActive }) => `flex items-center gap-2 px-2 py-2 rounded text-sm ${isActive ? "bg-line text-accent" : "text-slate-300 hover:bg-line"}`}><Icon size={16} />{label}</NavLink>)}
        <div className="pt-4 text-xs text-slate-400 px-2">{me.organization.name}<br />{me.email} · {me.role}</div>
        <button className="btn w-full flex items-center gap-2 justify-center mt-2" onClick={logout}><LogOut size={14} />Sign out</button>
      </aside>
      <main className="flex-1 p-4 md:p-6 min-w-0">
        <Routes>
          <Route path="/" element={<Overview />} /><Route path="/events" element={<Events />} /><Route path="/alerts" element={<Alerts />} />
          <Route path="/incidents" element={<Incidents />} /><Route path="/incidents/:id" element={<IncidentDetail />} /><Route path="/assets" element={<Assets />} />
          <Route path="/rules" element={<Rules />} /><Route path="/response" element={<Response />} /><Route path="/audit" element={<Audit />} />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </main>
    </div>
  );
}
