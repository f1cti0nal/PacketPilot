// PacketPilot — Cockpit. Composition root for the redesign demo. Owns shell
// state (sidebar collapse, active view, flyout selection, cross-filter) and lays
// out the severity-first mission canvas. Renders the placeholder capture.
import { useCallback, useEffect, useMemo, useState } from "react";
import { Table2, Filter } from "lucide-react";
import { basename } from "../lib/format";
import { SEVERITY_ORDER } from "../lib/severity";
import type { Incident, TabId } from "../types";

import { MOCK_OUTPUT } from "./mockData";
import { CommandBar } from "./CommandBar";
import { ThreatRail } from "./ThreatRail";
import { KpiCluster } from "./KpiCluster";
import { IncidentHero } from "./IncidentHero";
import { DetailFlyout } from "./DetailFlyout";
import { ActivityHeatmap } from "./ActivityHeatmap";
import { CategoryMatrix } from "./CategoryMatrix";
import { ProtocolMix } from "./ProtocolMix";
import { TopTalkersCard } from "./TopTalkersCard";
import { CaptureIntegrity } from "./CaptureIntegrity";
import { SectionLabel } from "./primitives";

const worstFirst = (a: Incident, b: Incident) =>
  SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.score - a.score;

export function CockpitApp() {
  const output = MOCK_OUTPUT;
  const s = output.summary;

  const [collapsed, setCollapsed] = useState(false);
  const [tab, setTab] = useState<TabId>("dashboard");

  // Per the cockpit spec, the threat rail auto-collapses to a 64px icon rail
  // below 1100px so the dense canvas keeps room on tablet/narrow widths.
  useEffect(() => {
    const mq = window.matchMedia("(max-width: 1100px)");
    const apply = () => setCollapsed(mq.matches);
    apply();
    mq.addEventListener("change", apply);
    return () => mq.removeEventListener("change", apply);
  }, []);
  const [selected, setSelected] = useState<Incident | null>(null);
  const [activeIp, setActiveIp] = useState<string | null>(null);
  const [flowsFilter, setFlowsFilter] = useState<string | null>(null);

  const incidents = useMemo(() => [...(s.incidents ?? [])].sort(worstFirst), [s.incidents]);
  const [hero, ...secondary] = incidents;
  const incidentByHost = useMemo(() => new Map(incidents.map((i) => [i.host, i])), [incidents]);

  const openHost = useCallback(
    (host: string) => {
      setActiveIp(host);
      const inc = incidentByHost.get(host);
      if (inc) setSelected(inc);
    },
    [incidentByHost],
  );

  const jumpToFlows = useCallback((filter: string) => {
    setFlowsFilter(filter);
    setSelected(null);
    setTab("flows");
  }, []);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <CommandBar
        captureName={basename(output.source_path)}
        sha256={output.source_sha256}
        activeTab={tab}
        onTab={setTab}
        collapsed={collapsed}
        onToggleCollapse={() => setCollapsed((c) => !c)}
      />

      <div className="flex min-h-0 flex-1">
        <ThreatRail
          threats={s.ip_threats ?? []}
          collapsed={collapsed}
          activeIp={activeIp}
          activeTab={tab}
          onTab={setTab}
          onSelect={openHost}
        />

        <main className="app-bg min-h-0 flex-1 overflow-y-auto">
          {tab === "dashboard" ? (
            <div className="flex flex-col gap-3 p-4 sm:p-5">
              <KpiCluster output={output} />

              {hero && (
                <IncidentHero
                  incident={hero}
                  primary={hero.severity === "critical"}
                  onPivot={jumpToFlows}
                  onOpen={() => setSelected(hero)}
                />
              )}

              {secondary.length > 0 && (
                <div>
                  <SectionLabel className="mb-2">Other incidents · {secondary.length}</SectionLabel>
                  <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                    {secondary.map((inc, i) => (
                      <IncidentHero key={`${inc.host}-${i}`} incident={inc} onPivot={jumpToFlows} onOpen={() => setSelected(inc)} />
                    ))}
                  </div>
                </div>
              )}

              <ActivityHeatmap histogram={s.time_histogram} bucketSecs={s.time_bucket_secs} findings={s.findings} />

              <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
                <div className="lg:col-span-7">
                  <CategoryMatrix breakdown={s.category_breakdown} onJump={jumpToFlows} />
                </div>
                <div className="lg:col-span-5">
                  <CaptureIntegrity output={output} />
                </div>
                <div className="lg:col-span-6">
                  <ProtocolMix proto={s.proto} />
                </div>
                <div className="lg:col-span-6">
                  <TopTalkersCard talkers={s.top_talkers} onSelect={openHost} />
                </div>
              </div>

              <p className="px-1 pb-2 text-center text-[11px] text-[var(--color-text-faint)]">
                Demo renders placeholder data typed against the real engine schema · PacketPilot — Cockpit redesign
              </p>
            </div>
          ) : (
            <FlowsPlaceholder filter={flowsFilter} onClear={() => setFlowsFilter(null)} />
          )}
        </main>
      </div>

      <DetailFlyout incident={selected} onClose={() => setSelected(null)} onJumpToFlows={jumpToFlows} />
    </div>
  );
}

function FlowsPlaceholder({ filter, onClear }: { filter: string | null; onClear: () => void }) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 p-8 text-center">
      <span className="flex h-14 w-14 items-center justify-center rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-surface-1)]">
        <Table2 size={26} className="text-[var(--color-text-faint)]" />
      </span>
      <div>
        <h2 className="font-display text-lg font-semibold text-[var(--color-text)]">Flows table</h2>
        <p className="t-body mt-1 max-w-sm text-[var(--color-text-dim)]">
          The existing virtualized flows view (≈39k rows via TanStack Virtual) mounts here, cross-filtered from the dashboard.
        </p>
      </div>
      {filter && (
        <div className="flex items-center gap-2 rounded-[var(--r-tile)] border border-[color:color-mix(in_srgb,var(--color-accent)_40%,var(--color-border))] bg-[color:color-mix(in_srgb,var(--color-accent)_8%,transparent)] px-3 py-1.5">
          <Filter size={13} className="text-[var(--color-accent)]" />
          <span className="font-mono-num text-xs text-[var(--color-text)]">filter: {filter}</span>
          <button type="button" onClick={onClear} className="text-xs text-[var(--color-text-faint)] underline-offset-2 hover:text-[var(--color-text)] hover:underline">
            clear
          </button>
        </div>
      )}
    </div>
  );
}

export default CockpitApp;
