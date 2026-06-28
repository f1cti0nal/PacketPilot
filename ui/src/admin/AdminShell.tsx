import { useEffect, useState } from "react";
import { Sidebar } from "./Sidebar";
import { AdminTopBar } from "./AdminTopBar";
import { AdminDashboard } from "./dashboard/AdminDashboard";
import { Placeholder } from "./views/Placeholder";
import { UsersView } from "./users/UsersView";
import { ADMIN_SECTIONS, sectionById, type AdminSectionId } from "./sections";

const VALID = new Set<string>(ADMIN_SECTIONS.map((s) => s.id));

function sectionFromHash(): AdminSectionId {
  const id = window.location.hash.replace(/^#/, "");
  return (VALID.has(id) ? id : "dashboard") as AdminSectionId;
}

export function AdminShell({ email, onSignOut }: { email: string; onSignOut: () => Promise<void> }) {
  const [active, setActive] = useState<AdminSectionId>(() => sectionFromHash());
  const [collapsed, setCollapsed] = useState(false);

  // Keep state in sync with browser back/forward hash changes.
  useEffect(() => {
    const onHash = () => setActive(sectionFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const select = (id: AdminSectionId) => {
    setActive(id);
    if (window.location.hash !== `#${id}`) window.location.hash = id;
  };

  const section = sectionById(active);
  const title = section?.label ?? "Dashboard";

  return (
    <div className="flex h-full min-h-0 bg-bg text-[var(--color-text)]">
      <Sidebar active={active} onSelect={select} collapsed={collapsed} onToggleCollapse={() => setCollapsed((c) => !c)} />
      <div className="flex min-h-0 flex-1 flex-col">
        <AdminTopBar title={title} email={email} onSignOut={onSignOut} />
        <main className="min-h-0 flex-1 overflow-y-auto p-4">
          {active === "dashboard" ? (
            <AdminDashboard />
          ) : active === "users" ? (
            <UsersView adminEmail={email} />
          ) : (
            <Placeholder title={title} phase={section?.phase ?? 0} />
          )}
        </main>
      </div>
    </div>
  );
}

export default AdminShell;
