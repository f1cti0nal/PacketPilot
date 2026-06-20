import { useMemo, useState } from "react";

import type { AnalysisOutput, Incident, IpThreat, Severity } from "../types";
import { SEVERITY_ORDER } from "../lib/severity";
import { humanBytes, humanNumber } from "../lib/format";

import { sevColor } from "../redesign/viz";
import { Card, SectionLabel, ScoreBar, IocDot, MitreTag } from "../redesign/primitives";
import { KpiCluster } from "../redesign/KpiCluster";
import { IncidentHero } from "../redesign/IncidentHero";
import { DetailFlyout } from "../redesign/DetailFlyout";
import { ActivityHeatmap } from "../redesign/ActivityHeatmap";
import { CategoryMatrix } from "../redesign/CategoryMatrix";
import { ProtocolMix } from "../redesign/ProtocolMix";
import { TopTalkersCard } from "../redesign/TopTalkersCard";
import { CaptureIntegrity } from "../redesign/CaptureIntegrity";

/**
 * Navigation request raised from the dashboard when the analyst drills into a
 * slice of the capture (a severity band, a traffic category, or a host). The
 * parent (App) honors it by switching to the Flows view with the filter applied.
 */
export interface DashboardDrilldown {
  severity?: Severity;
  category?: string;
  ip?: string;
}

export interface DashboardProps {
  /** The engine's AnalysisOutput (parsed from summary.json). */
  output: AnalysisOutput;
  /** Optional drill-down handler; wired to the Flows view by the App. */
  onJumpToFlows?: (filter: DashboardDrilldown) => void;
}

const worstFirst = (
  a: { severity: Severity; score: number },
  b: { severity: Severity; score: number },
) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || b.score - a.score;

/**
 * The "PacketPilot — Cockpit" home: a severity-first mission canvas over the
 * engine output. KPI cluster → kill-chain incident hero → threat watchlist →
 * activity heatmap → category / integrity / protocol / talkers, with a right
 * detail flyout for any incident. Pure composition over `output`.
 */
export function Dashboard({ output, onJumpToFlows }: DashboardProps) {
  const s = output.summary;
  const [selected, setSelected] = useState<Incident | null>(null);

  const incidents = useMemo(() => [...(s.incidents ?? [])].sort(worstFirst), [s.incidents]);
  const [hero, ...secondary] = incidents;
  const incidentByHost = useMemo(() => new Map(incidents.map((i) => [i.host, i])), [incidents]);

  // Selecting a host opens its incident in the flyout when one exists.
  const openHost = (host: string) => {
    const inc = incidentByHost.get(host);
    if (inc) setSelected(inc);
  };
  const toFlowsIp = (ip: string) => onJumpToFlows?.({ ip });
  const toFlowsCat = (category: string) => onJumpToFlows?.({ category });

  return (
    <div className="app-bg min-h-full">
      <div className="mx-auto flex max-w-[1600px] flex-col gap-3 p-4 sm:p-5">
        {/* Zone 1 — instrument-cluster KPIs + incident verdict + context ring */}
        <KpiCluster output={output} />

        {/* Zone 2 — kill-chain incident hero (only the top critical breathes) */}
        {hero && (
          <IncidentHero
            incident={hero}
            primary={hero.severity === "critical"}
            onPivot={toFlowsIp}
            onOpen={() => setSelected(hero)}
          />
        )}
        {secondary.length > 0 && (
          <div>
            <SectionLabel className="mb-2">Other incidents · {secondary.length}</SectionLabel>
            <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
              {secondary.map((inc, i) => (
                <IncidentHero
                  key={`${inc.host}-${i}`}
                  incident={inc}
                  onPivot={toFlowsIp}
                  onOpen={() => setSelected(inc)}
                />
              ))}
            </div>
          </div>
        )}

        {/* Threat watchlist — the ranked scored hosts (the rail, as a card) */}
        <ThreatWatchlist threats={s.ip_threats ?? []} onSelect={openHost} />

        {/* Zone 3 — activity heatmap ribbon */}
        <ActivityHeatmap
          histogram={s.time_histogram}
          bucketSecs={s.time_bucket_secs}
          findings={s.findings}
        />

        {/* Zones 4 & 5 — category / integrity / protocol / talkers */}
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-12">
          <div className="lg:col-span-7">
            <CategoryMatrix breakdown={s.category_breakdown} onJump={toFlowsCat} />
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
      </div>

      <DetailFlyout incident={selected} onClose={() => setSelected(null)} onJumpToFlows={toFlowsIp} />
    </div>
  );
}

/** The ranked threat watchlist, surfaced as a grid of compact host cards. */
function ThreatWatchlist({
  threats,
  onSelect,
}: {
  threats: IpThreat[];
  onSelect: (ip: string) => void;
}) {
  const top = useMemo(() => [...threats].sort(worstFirst).slice(0, 9), [threats]);
  if (top.length === 0) return null;

  return (
    <Card
      label="THREATS"
      title="Threat watchlist"
      right={
        <span className="font-mono-num t-tag text-[var(--color-text-dim)]">
          {humanNumber(threats.length)} scored
        </span>
      }
    >
      <ul className="grid grid-cols-1 gap-2 md:grid-cols-2 xl:grid-cols-3">
        {top.map((t) => {
          const color = sevColor(t.severity);
          return (
            <li key={t.ip}>
              <button
                type="button"
                onClick={() => onSelect(t.ip)}
                aria-label={`${t.ip}, ${t.severity}, score ${t.score} of 100${t.ioc ? ", on an indicator feed" : ""}`}
                className="flex w-full flex-col gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-2.5 text-left transition-colors hover:border-[var(--color-border-strong)]"
                style={{ borderLeftColor: color, borderLeftWidth: 2 }}
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono-num min-w-0 flex-1 truncate text-[13px] text-[var(--color-text)]">
                    {t.ip}
                  </span>
                  {t.ioc && <IocDot />}
                  <span className="font-mono-num shrink-0 text-xs font-semibold tabular-nums" style={{ color }}>
                    {t.score}
                  </span>
                </div>
                <ScoreBar score={t.score} severity={t.severity} />
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="t-tag uppercase text-[var(--color-text-faint)]">{t.ip_class}</span>
                  <span className="font-mono-num t-tag text-[var(--color-text-faint)]">
                    {humanNumber(t.flows)} fl · {humanBytes(t.bytes)}
                  </span>
                  {t.attack.slice(0, 3).map((a) => (
                    <MitreTag key={a} id={a} />
                  ))}
                </div>
              </button>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

export default Dashboard;
