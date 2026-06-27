import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { Landing } from "./landing/Landing";
import { ErrorBoundary } from "./components/state/ErrorBoundary";
import "./index.css";

// Minimal pathname routing: "/" serves the marketing landing page; "/app" (and anything
// below it) serves the triage application. The landing's CTAs are plain links to /app, so a
// full navigation boots the app — no client-side router library needed. On Vercel, /app is
// rewritten to /index.html (see vercel.json) so this same bundle loads and branches here.
const path = window.location.pathname.replace(/\/+$/, "");
const isApp = path === "/app" || path.startsWith("/app/");

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>{isApp ? <App /> : <Landing />}</ErrorBoundary>
  </React.StrictMode>,
);
