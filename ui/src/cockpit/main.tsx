// Standalone entry for the "PacketPilot — Cockpit" redesign demo. Mounts the
// cockpit against placeholder data, independent of the Tauri-wired production app.
import React from "react";
import ReactDOM from "react-dom/client";
import { CockpitApp } from "./CockpitApp";
import "./theme.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <CockpitApp />
  </React.StrictMode>,
);
