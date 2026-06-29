import React, { Suspense } from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { Landing } from "./landing/Landing";
import { ErrorBoundary } from "./components/state/ErrorBoundary";
import { LoadingState } from "./components/state/LoadingState";
import { resolveRoute } from "./lib/route";
import "./index.css";

// Pathname routing: "/" → marketing landing, "/app" → triage app, "/admin" → the
// (lazy-loaded, role-gated) admin panel. On Vercel, /app and /admin are rewritten
// to /index.html (see vercel.json) so this same bundle loads and branches here.
const AdminApp = React.lazy(() => import("./admin/AdminApp"));
const AccountApp = React.lazy(() => import("./account/AccountApp"));
const LegalApp = React.lazy(() => import("./legal/LegalApp"));
const route = resolveRoute(window.location.pathname);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      {route === "admin" ? (
        <Suspense fallback={<LoadingState label="Loading admin…" />}>
          <AdminApp />
        </Suspense>
      ) : route === "account" ? (
        <Suspense fallback={<LoadingState label="Loading account…" />}>
          <AccountApp />
        </Suspense>
      ) : route === "legal" ? (
        <Suspense fallback={<LoadingState label="Loading…" />}>
          <LegalApp />
        </Suspense>
      ) : route === "app" ? (
        <App />
      ) : (
        <Landing />
      )}
    </ErrorBoundary>
  </React.StrictMode>,
);
