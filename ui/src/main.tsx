import React, { Suspense } from "react";
import ReactDOM from "react-dom/client";
import { AppGate } from "./auth/AppGate";
import { Landing } from "./landing/Landing";
import { ErrorBoundary } from "./components/state/ErrorBoundary";
import { LoadingState } from "./components/state/LoadingState";
import { SpeedInsights } from "@vercel/speed-insights/react";
import { resolveRouteFor } from "./lib/route";
import { purgeLegacyGlobalStores } from "./lib/storageScope";
import "./index.css";

// One-time cleanup of pre-namespacing browser stores (see storageScope). Runs before anything
// reads persistence, so the orphaned global capture data from before per-account namespacing is
// removed rather than left on a shared machine.
purgeLegacyGlobalStores();

// Pathname routing: "/" → marketing landing, "/app" → triage app, "/admin" → the
// (lazy-loaded, role-gated) admin panel. On Vercel, /app and /admin are rewritten
// to /index.html (see vercel.json) so this same bundle loads and branches here.
const AdminApp = React.lazy(() => import("./admin/AdminApp"));
const AccountApp = React.lazy(() => import("./account/AccountApp"));
const AuthApp = React.lazy(() => import("./auth/AuthApp"));
const LegalApp = React.lazy(() => import("./legal/LegalApp"));
const PricingApp = React.lazy(() => import("./pricing/PricingApp"));
const ToolApp = React.lazy(() => import("./seo/ToolApp"));
const BlogApp = React.lazy(() => import("./blog/BlogApp"));
const route = resolveRouteFor(window.location.hostname, window.location.pathname);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      {route === "auth" ? (
        <Suspense fallback={<LoadingState label="Loading…" />}>
          <AuthApp />
        </Suspense>
      ) : route === "admin" ? (
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
      ) : route === "pricing" ? (
        <Suspense fallback={<LoadingState label="Loading…" />}>
          <PricingApp />
        </Suspense>
      ) : route === "tool" ? (
        <Suspense fallback={<LoadingState label="Loading…" />}>
          <ToolApp />
        </Suspense>
      ) : route === "blog" ? (
        <Suspense fallback={<LoadingState label="Loading…" />}>
          <BlogApp />
        </Suspense>
      ) : route === "app" ? (
        <AppGate />
      ) : (
        <Landing />
      )}
    </ErrorBoundary>
    {/* Same-origin performance telemetry (/_vercel/speed-insights/*); no capture data. */}
    <SpeedInsights />
  </React.StrictMode>,
);
