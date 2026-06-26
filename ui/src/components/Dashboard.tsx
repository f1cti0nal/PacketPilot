import { useCallback, useMemo, useState } from "react";
import { Scissors } from "lucide-react";

import type { ActiveSource, AnalysisOutput, Incident, IpThreat, Severity } from "../types";
import { carveSubPcap, packetsAvailable } from "../lib/packets";
import { SEVERITY_ORDER } from "../lib/severity";
import { humanBytes, humanNumber } from "../lib/format";

import { sevColor } from "../cockpit/viz";
import { Card, SectionLabel, ScoreBar, IocDot, MitreTag } from "../cockpit/primitives";
import { KpiCluster } from "../cockpit/KpiCluster";
import { IncidentHero } from "../cockpit/IncidentHero";
import { DetailFlyout } from "../cockpit/DetailFlyout";
import { ActivityHeatmap } from "../cockpit/ActivityHeatmap";
import { CategoryMatrix } from "../cockpit/CategoryMatrix";
import { ProtocolMix } from "../cockpit/ProtocolMix";
import { TopTalkersCard } from "../cockpit/TopTalkersCard";
import { CaptureIntegrity } from "../cockpit/CaptureIntegrity";
import { AiSummaryCard } from "../cockpit/AiSummaryCard";
import { ThreatGraph } from "../cockpit/ThreatGraph";
import { ProtocolSunburst } from "../cockpit/ProtocolSunburst";
import { TopPortsCard } from "../cockpit/TopPortsCard";
import { HttpOverviewCard } from "../cockpit/HttpOverviewCard";
import { DnsResolutionsCard } from "../cockpit/DnsResolutionsCard";
import { EncryptedDnsCard } from "../cockpit/EncryptedDnsCard";
import { CarvedFilesCard } from "../cockpit/CarvedFilesCard";
import { LocalHostsCard } from "../cockpit/LocalHostsCard";
import { DownloadsCard } from "../cockpit/DownloadsCard";
import { TriageBadge } from "../cockpit/TriageAnnotation";
import { captureKey } from "../lib/ai/cache";
import { DomainThreatsPanel } from "./triage/DomainThreatsPanel";
import { SignatureMatchesPanel } from "./triage/SignatureMatchesPanel";
import { CertHealthPanel } from "./triage/CertHealthPanel";

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

/** Carve window upper bound — above any real ns-since-epoch (~1.8e18), below i64::MAX (9.22e18). */
const HOST_CARVE_END_NS = 9e18;

export interface DashboardProps {
  /** The engine's AnalysisOutput (parsed from summary.json). */
  output: AnalysisOutput;
  /** Optional drill-down handler; wired to the Flows view by the App. */
  onJumpToFlows?: (filter: DashboardDrilldown) => void;
  /** Controlled flyout incident (lifted to App so shell/palette can share it). */
  selectedIncident: Incident | null;
  /** Setter for the controlled flyout incident. */
  onSelectIncident: (incident: Incident | null) => void;
  /** Active capture source — enables per-host pcap carve when retained (carve disabled without it). */
  activeSource?: ActiveSource;
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
export function Dashboard({
  output,
  onJumpToFlows,
  selectedIncident,
  onSelectIncident,
  activeSource,
}: DashboardProps) {
  const s = output.summary;

  const incidents = useMemo(() => [...(s.incidents ?? [])].sort(worstFirst), [s.incidents]);
  const [hero, ...secondary] = incidents;
  const incidentByHost = useMemo(() => new Map(incidents.map((i) => [i.host, i])), [incidents]);
  const threatByHost = useMemo(() => new Map((s.ip_threats ?? []).map((t) => [t.ip, t])), [s.ip_threats]);
  // Passive-DNS domain + L2 MAC, keyed by host IP, for inline identity in the flyout.
  const domainByIp = useMemo(
    () => new Map((s.resolved_ips ?? []).map((r) => [r.ip, r.domain])),
    [s.resolved_ips],
  );
  const macByIp = useMemo(
    () => new Map((s.arp_hosts ?? []).map((h) => [h.ip, h.mac])),
    [s.arp_hosts],
  );

  // Selecting a host opens its incident in the flyout when one exists.
  const openHost = (host: string) => {
    const inc = incidentByHost.get(host);
    if (inc) onSelectIncident(inc);
  };
  const toFlowsIp = (ip: string) => onJumpToFlows?.({ ip });
  const toFlowsCat = (category: string) => onJumpToFlows?.({ category });

  // Per-host pcap carve — reuses the retained capture source (disabled when not retained).
  const canCarve = packetsAvailable(activeSource ?? null);
  const [carveNotice, setCarveNotice] = useState<string | null>(null);
  const carveHost = useCallback(
    async (ip: string) => {
      const res = await carveSubPcap(
        { host: ip, start_ns: 0, end_ns: HOST_CARVE_END_NS },
        activeSource ?? null,
        `${ip}-carve.pcap`,
      );
      if (res.message) setCarveNotice(res.message);
    },
    [activeSource],
  );

  return (
    <div className="app-bg min-h-full">
      <div className="mx-auto flex max-w-[1600px] flex-col gap-[var(--density-gap)] p-4 sm:p-5">
        {/* Zone 1 — instrument-cluster KPIs + incident verdict + context ring */}
        <KpiCluster output={output} />
        <AiSummaryCard output={output} captureId={captureKey(output)} />

        {/* Zone 2 — kill-chain incident hero (only the top critical breathes) */}
        {hero && (
          <IncidentHero
            incident={hero}
            primary={hero.severity === "critical"}
            onPivot={toFlowsIp}
            onOpen={() => onSelectIncident(hero)}
          />
        )}
        {secondary.length > 0 && (
          <div>
            <SectionLabel className="mb-2">Other incidents · {secondary.length}</SectionLabel>
            <div className="grid grid-cols-1 gap-[var(--density-gap)] xl:grid-cols-2">
              {secondary.map((inc, i) => (
                <IncidentHero
                  key={`${inc.host}-${i}`}
                  incident={inc}
                  onPivot={toFlowsIp}
                  onOpen={() => onSelectIncident(inc)}
                />
              ))}
            </div>
          </div>
        )}

        {/* Threat watchlist — the ranked scored hosts (the rail, as a card) */}
        <ThreatWatchlist
          threats={s.ip_threats ?? []}
          onSelect={openHost}
          onCarveHost={carveHost}
          canCarve={canCarve}
          captureKey={captureKey(output)}
        />
        {carveNotice && (
          <p role="status" className="px-1 text-xs text-[var(--color-text-faint)]">
            {carveNotice}
          </p>
        )}

        {/* Threat relationship graph — spatial map of who is doing what to whom */}
        <ThreatGraph findings={s.findings ?? []} threats={s.ip_threats ?? []} onJump={toFlowsIp} />

        {/* Zone 3 — activity heatmap ribbon */}
        <ActivityHeatmap
          histogram={s.time_histogram}
          bucketSecs={s.time_bucket_secs}
          findings={s.findings}
        />

        {/* Zones 4 & 5 — category / integrity / protocol / talkers */}
        <div className="grid grid-cols-1 gap-[var(--density-gap)] lg:grid-cols-12">
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
          <div className="lg:col-span-6">
            <ProtocolSunburst hierarchy={s.protocol_hierarchy ?? []} />
          </div>
          <div className="lg:col-span-6">
            <TopPortsCard ports={s.port_histogram ?? []} />
          </div>
          <div className="lg:col-span-12">
            <HttpOverviewCard hosts={s.http_hosts ?? []} userAgents={s.user_agents ?? []} />
          </div>
        </div>
        <SignatureMatchesPanel findings={s.findings ?? []} onJump={toFlowsIp} />
        <CertHealthPanel findings={s.findings ?? []} onJump={toFlowsIp} />
        <DomainThreatsPanel domains={s.domain_threats ?? []} />
        <DnsResolutionsCard resolved={s.resolved_ips ?? []} />
        <EncryptedDnsCard hosts={s.encrypted_dns ?? []} />
        <CarvedFilesCard files={s.carved_files ?? []} />
        <LocalHostsCard hosts={s.arp_hosts ?? []} />
        <DownloadsCard downloads={s.downloads ?? []} />
      </div>

      <DetailFlyout
        incident={selectedIncident}
        onClose={() => onSelectIncident(null)}
        onJumpToFlows={toFlowsIp}
        scoreEvidence={selectedIncident ? threatByHost.get(selectedIncident.host)?.evidence : undefined}
        hostScore={selectedIncident ? threatByHost.get(selectedIncident.host)?.score : undefined}
        scoreTerms={selectedIncident ? threatByHost.get(selectedIncident.host)?.score_terms : undefined}
        resolvedDomain={selectedIncident ? domainByIp.get(selectedIncident.host) : undefined}
        mac={selectedIncident ? macByIp.get(selectedIncident.host) : undefined}
        captureKey={captureKey(output)}
      />
    </div>
  );
}

/** The ranked threat watchlist, surfaced as a grid of compact host cards. */
function ThreatWatchlist({
  threats,
  onSelect,
  onCarveHost,
  canCarve,
  captureKey,
}: {
  threats: IpThreat[];
  onSelect: (ip: string) => void;
  onCarveHost?: (ip: string) => void;
  canCarve?: boolean;
  captureKey: string;
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
      <ul className="grid grid-cols-1 gap-[var(--density-gap-sm)] md:grid-cols-2 xl:grid-cols-3">
        {top.map((t) => {
          const color = sevColor(t.severity);
          return (
            <li key={t.ip} className="relative">
              <button
                type="button"
                onClick={() => onSelect(t.ip)}
                aria-label={`${t.ip}, ${t.severity}, score ${t.score} of 100${t.ioc ? ", on an indicator feed" : ""}`}
                className="flex w-full flex-col gap-1.5 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] p-[var(--density-pad)] text-left transition-colors hover:border-[var(--color-border-strong)]"
                style={{ borderLeftColor: color, borderLeftWidth: 2 }}
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono-num min-w-0 flex-1 truncate text-[13px] text-[var(--color-text)]">
                    {t.ip}
                  </span>
                  <TriageBadge captureKey={captureKey} ip={t.ip} />
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
              {onCarveHost && (
                <button
                  type="button"
                  aria-label={`Carve ${t.ip} host packets`}
                  title={
                    canCarve
                      ? "Carve this host's packets (.pcap)"
                      : "Packets are only available for captures analyzed from a pcap"
                  }
                  disabled={!canCarve}
                  onClick={(e) => {
                    e.stopPropagation();
                    onCarveHost(t.ip);
                  }}
                  className={`absolute bottom-1.5 right-1.5 rounded border border-[var(--color-border)] bg-[var(--color-surface-2)] p-1 transition-colors ${
                    canCarve
                      ? "text-[var(--color-text-faint)] hover:border-[var(--color-border-strong)] hover:text-[var(--color-accent)]"
                      : "cursor-not-allowed text-[var(--color-text-faint)] opacity-40"
                  }`}
                >
                  <Scissors size={12} />
                </button>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

export default Dashboard;
