import { useAdminSession } from "./useAdminSession";
import { AdminLogin } from "./AdminLogin";
import { AdminShell } from "./AdminShell";
import { LoadingState } from "../components/state/LoadingState";

export function AdminApp() {
  const session = useAdminSession();
  if (session.status === "loading") return <LoadingState label="Checking access…" />;
  if (session.status === "admin") return <AdminShell email={session.email} onSignOut={session.signOut} />;
  return <AdminLogin session={session} />;
}

export default AdminApp;
