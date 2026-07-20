import React, { Suspense } from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { Landing } from "./landing/Landing";
import { ErrorBoundary } from "./components/state/ErrorBoundary";
import { LoadingState } from "./components/state/LoadingState";
import { SpeedInsights } from "@vercel/speed-insights/react";
import { resolveRouteFor } from "./lib/route";
import { purgeLegacyGlobalStores } from "./lib/storageScope";
import { initGaFromStoredConsent } from "./lib/analytics/ga";
import { ConsentBanner } from "./components/ConsentBanner";
import "./index.css";

// One-time cleanup of pre-namespacing browser stores (see storageScope). Runs before anything
// reads persistence, so the orphaned global capture data from before per-account namespacing is
// removed rather than left on a shared machine.
purgeLegacyGlobalStores();

// Resume Google Analytics for returning visitors who previously granted consent. No-op when GA
// is unconfigured or consent was not granted (fresh/declined visitors see the ConsentBanner).
// Runs before render so the entrance page view fires before route components mount.
initGaFromStoredConsent();

// Pathname routing: "/" → marketing landing, "/app" → triage app (free for everyone, no
// sign-in), "/admin" → the (lazy-loaded, role-gated) operator admin panel. On Vercel, /app and
// /admin are rewritten to /index.html (see vercel.json) so this same bundle loads and branches
// here.
const AdminApp = React.lazy(() => import("./admin/AdminApp"));
const LegalApp = React.lazy(() => import("./legal/LegalApp"));
const ToolApp = React.lazy(() => import("./seo/ToolApp"));
const BlogApp = React.lazy(() => import("./blog/BlogApp"));
const route = resolveRouteFor(window.location.hostname, window.location.pathname);

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      {route === "admin" ? (
        <Suspense fallback={<LoadingState label="Loading admin…" />}>
          <AdminApp />
        </Suspense>
      ) : route === "legal" ? (
        <Suspense fallback={<LoadingState label="Loading…" />}>
          <LegalApp />
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
        <App />
      ) : (
        <Landing />
      )}
    </ErrorBoundary>
    {/* Same-origin performance telemetry (/_vercel/speed-insights/*); no capture data. */}
    <SpeedInsights />
    {/* Google Analytics consent banner — hard opt-in; renders only when GA is configured and
        the visitor has not yet chosen. GA loads nothing until they accept. */}
    <ConsentBanner />
  </React.StrictMode>,
);
