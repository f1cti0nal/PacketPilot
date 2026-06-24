import { useCallback, useEffect, useRef, useState } from "react";
import type {
  ActiveSource,
  AnalysisOutput,
  FlowRow,
  Incident,
  RecentEntry,
  RecentOrigin,
  Severity,
  SummaryState,
  FlowsState,
  TabId,
} from "./types";
import { loadSummary, loadFlows } from "./lib/data";
import { basename } from "./lib/format";
import {
  entryId,
  getFlows,
  listRecent,
  putFlows,
  recordRecent,
  removeRecent,
  clearRecent,
} from "./lib/recent";
import { AppShell } from "./components/layout/AppShell";
import { LoadingState } from "./components/state/LoadingState";
import { ErrorState } from "./components/state/ErrorState";
import { Dashboard } from "./components/Dashboard";
import { FlowsView } from "./views/FlowsView";
import { RecentView } from "./components/recent/RecentView";
import { CompareView } from "./views/CompareView";
import {
  isTauri,
  openCaptureDialog,
  analyzeViaTauri,
  exportReport,
  exportCsv,
  exportStix,
  exportMisp,
  exportCef,
  copyCsv,
  copyStix,
  copyMisp,
  copyCef,
  applyRules,
} from "./lib/platform";
import { packetsAvailable } from "./lib/packets";
import { analyzeViaWasm, applyReputationWasm, applyDomainReputationWasm } from "./lib/wasmEngine";
import { EmptyState } from "./components/state/EmptyState";
import {
  repEnabled,
  getProxyUrl,
  browserKeys,
  consentGiven,
  giveConsent,
  domainEnabled,
  domainConsentGiven,
  giveDomainConsent,
  getKey,
} from "./lib/reputation/settings";
import { lookupReputation, lookupDomainReputation } from "./lib/reputation/orchestrator";
import { proxyHttp } from "./lib/reputation/http";
import { ReputationConsent } from "./cockpit/ReputationConsent";
import { DomainConsent } from "./cockpit/DomainConsent";
import { SettingsDialog } from "./cockpit/SettingsDialog";
import { AiChatPanel } from "./cockpit/AiChatPanel";
import { getAiSummary, captureKey } from "./lib/ai/cache";
import { pickRuleBase } from "./lib/ruleBase";
import { saveRuleSet, type RuleSet } from "./lib/ruleSets";
import { RuleSetsMenu } from "./components/flows/RuleSetsMenu";

const repCaptureKey = (o: AnalysisOutput): string | undefined => o.source_sha256 ?? o.source_path;

export interface FlowsInitialFilter {
  severity?: Severity;
  category?: string;
  proto?: number;
  ip?: string;
}

const SUMMARY_URL = "/sample/summary.json";
const FLOWS_URL = "/sample/flows.parquet";

const IS_TAURI = isTauri();

/** Cap on browser-retained pcap bytes for packet drill-down; larger captures skip retention. */
const MAX_RETAIN_BYTES = 64 * 1024 * 1024;

/** Everything needed to install a freshly-analyzed (or restored) capture as the active one. */
interface ApplyCaptureInput {
  summary: AnalysisOutput;
  flows?: FlowRow[];
  /** Absolute file path (desktop) — enables in-place re-analyze from the Recent tab. */
  path?: string;
  /** Display name override (e.g. the dropped file's name). */
  fileName?: string;
  sizeBytes?: number;
  sha256?: string;
  origin: RecentOrigin;
  /** Capture source retained for on-demand packet extraction; null disables drill-down. */
  source?: ActiveSource;
}

export function App() {
  const [tab, setTab] = useState<TabId>("dashboard");
  const [flowsFilter, setFlowsFilter] = useState<FlowsInitialFilter | undefined>(
    undefined,
  );
  const [compareIds, setCompareIds] = useState<[string, string] | null>(null);
  const [compareSwapped, setCompareSwapped] = useState(false);
  const startCompare = useCallback((beforeId: string, afterId: string) => {
    setCompareIds([beforeId, afterId]);
    setCompareSwapped(false);
    setTab("compare");
  }, []);

  // App owns both datasets so the AppShell upload affordance can replace them.
  const [summary, setSummary] = useState<SummaryState>({ status: "idle" });
  const [flows, setFlows] = useState<FlowsState>({ status: "idle", rows: [] });
  // The active capture's source (pcap path or retained bytes), enabling per-flow packet
  // drill-down. null whenever packets can't be re-extracted (sample, summary import, etc.).
  const [activeSource, setActiveSource] = useState<ActiveSource>(null);

  // Recent captures: the persisted list, which entry is currently shown, and which (if any)
  // is mid-re-analysis. The load dialog's open state is lifted here so the Recent tab can
  // trigger it too.
  const [recent, setRecent] = useState<RecentEntry[]>(() => listRecent());
  const [activeId, setActiveId] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [loadDialogOpen, setLoadDialogOpen] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [collapsed, setCollapsed] = useState(false);
  const [activeIp, setActiveIp] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [aiChatOpen, setAiChatOpen] = useState(false);
  // Consent prompt state: set when a newly-loaded capture has public IPs but consent hasn't
  // been given yet; cleared when the user proceeds or cancels.
  const [consentPrompt, setConsentPrompt] = useState<{ output: AnalysisOutput; ipCount: number; providers: string[] } | null>(null);
  // Domain consent prompt: set when a capture has domain threats but domain consent hasn't been given.
  const [domainConsentPrompt, setDomainConsentPrompt] = useState<{ output: AnalysisOutput; domainCount: number } | null>(null);
  // Tracks the source identity of the last capture we ran (or offered to run) the reputation
  // pass on, preventing double-triggers when summary state re-renders.
  const lastRepSourceRef = useRef<string | null>(null);
  // The freshest "ready" summary, so each reputation pass enriches the latest data (not a stale
  // snapshot); a chain serializes the IP and domain commits so they compose, never clobber.
  const summaryDataRef = useRef<AnalysisOutput | null>(null);
  const repChainRef = useRef<Promise<void>>(Promise.resolve());

  // Rule-loading: base snapshot prevents re-stacking (each reload applies over the original
  // reputation-enriched summary, not the previously-rules-augmented one).
  const ruleBaseRef = useRef<{ key: string; data: AnalysisOutput } | null>(null);
  const [ruleNotice, setRuleNotice] = useState<string | null>(null);
  const rulesInputRef = useRef<HTMLInputElement | null>(null);

  // Eagerly load the bundled sample capture on mount.
  useEffect(() => {
    if (IS_TAURI) return; // desktop shows empty state until a capture is opened
    let cancelled = false;

    setActiveSource(null); // the bundled sample has no re-extractable source
    setSummary({ status: "loading" });
    loadSummary(SUMMARY_URL)
      .then((data) => {
        if (!cancelled) setSummary({ status: "ready", data });
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setSummary({
            status: "error",
            error: String((err as Error)?.message ?? err),
          });
      });

    setFlows({ status: "loading", rows: [] });
    loadFlows(FLOWS_URL)
      .then((rows) => {
        if (!cancelled) setFlows({ status: "ready", rows });
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setFlows({
            status: "error",
            rows: [],
            error: String((err as Error)?.message ?? err),
          });
      });

    return () => {
      cancelled = true;
    };
  }, []);

  // Keep summaryDataRef in sync so enrichAndCommit always enriches the freshest data.
  useEffect(() => {
    summaryDataRef.current = summary.status === "ready" ? (summary.data ?? null) : null;
  }, [summary]);

  // Auto-collapse the threat rail on narrow viewports.
  useEffect(() => {
    const mq = window.matchMedia("(max-width: 1100px)");
    const apply = () => setCollapsed(mq.matches);
    apply();
    mq.addEventListener("change", apply);
    return () => mq.removeEventListener("change", apply);
  }, []);

  // Install a capture as the active dataset AND record it in the Recent list (caching its
  // flows in IndexedDB for instant reopen). The single funnel for every load path.
  const applyCapture = useCallback(
    async (input: ApplyCaptureInput): Promise<void> => {
      const data = input.summary;
      setSummary({ status: "ready", data });
      if (input.flows) setFlows({ status: "ready", rows: input.flows });
      setSelectedIncident(null);
      setActiveIp(null);
      setActiveSource(input.source ?? null);

      const name = input.fileName ?? basename(data.source_path);
      const sizeBytes = input.sizeBytes ?? data.source_bytes;
      const sha256 = input.sha256 ?? data.source_sha256 ?? undefined;
      const id = entryId({ sha256, name, sizeBytes });
      const flowCount = input.flows
        ? input.flows.length
        : data.summary.total_flows;

      let flowsCached = false;
      if (input.flows && input.flows.length > 0) {
        flowsCached = await putFlows(id, input.flows);
      }

      const list = recordRecent({
        id,
        name,
        path: input.path,
        sizeBytes,
        sha256,
        origin: input.origin,
        summary: data,
        flowCount,
        flowsCached,
      });
      setRecent(list);
      setActiveId(id);
    },
    [],
  );

  // Apply a reputation fold to the freshest summary for THIS capture and commit it, serialized
  // through repChainRef so the IP and domain passes compose instead of overwriting each other.
  const enrichAndCommit = useCallback(
    (
      base: AnalysisOutput,
      verdicts: Record<string, import("./types").ReputationVerdict[]>,
      apply: (json: string, v: Record<string, import("./types").ReputationVerdict[]>) => Promise<AnalysisOutput>,
    ): Promise<void> => {
      const run = repChainRef.current.then(async () => {
        const latest = summaryDataRef.current;
        const useBase = latest && repCaptureKey(latest) === repCaptureKey(base) ? latest : base;
        const enriched = await apply(JSON.stringify(useBase), verdicts);
        summaryDataRef.current = enriched;
        setSummary({ status: "ready", data: enriched });
      });
      repChainRef.current = run.catch(() => {});
      return run;
    },
    [],
  );

  // Perform the reputation lookup and apply enriched results to the current summary IN PLACE.
  // Does NOT call applyCapture again — that would re-record to Recent and reset activeSource.
  const runReputation = useCallback(async (output: AnalysisOutput): Promise<void> => {
    if (!repEnabled()) return;
    const ips = (output.summary.ip_threats ?? [])
      .filter((t) => t.ip_class === "public")
      .map((t) => t.ip);
    if (ips.length === 0) return;

    let verdicts: Record<string, import("./types").ReputationVerdict[]> = {};
    const now = Math.floor(Date.now() / 1000);
    if (IS_TAURI) {
      const { invoke } = await import("@tauri-apps/api/core");
      verdicts = JSON.parse(await invoke<string>("reputation_lookup", { ips })) as typeof verdicts;
    } else {
      const proxy = getProxyUrl();
      const keys = browserKeys();
      if (!proxy || Object.keys(keys).length === 0) return;
      verdicts = await lookupReputation(proxyHttp(proxy), ips, keys, now);
    }

    if (Object.keys(verdicts).length === 0) return;
    await enrichAndCommit(output, verdicts, applyReputationWasm);
  }, [enrichAndCommit]);

  // Open the consent gate or fire the reputation pass immediately, depending on whether
  // consent has already been given. Should be called once per new capture (after applyCapture).
  const triggerReputationGate = useCallback((output: AnalysisOutput) => {
    if (!repEnabled()) return;
    const publicIps = (output.summary.ip_threats ?? []).filter((t) => t.ip_class === "public");
    if (publicIps.length === 0) return;
    if (consentGiven()) {
      void runReputation(output);
    } else {
      // Fetch the actual configured provider list so the consent dialog names only
      // providers the user has set up (desktop: keychain; browser: localStorage keys).
      const fetchProviders = IS_TAURI
        ? import("@tauri-apps/api/core").then(({ invoke }) => invoke<string[]>("reputation_key_status"))
        : Promise.resolve(Object.keys(browserKeys()));
      void fetchProviders.then((providers) => {
        setConsentPrompt({ output, ipCount: publicIps.length, providers });
      });
    }
  }, [runReputation]);

  // Perform domain reputation lookup and apply enriched results to the current summary IN PLACE.
  const runDomainReputation = useCallback(async (output: AnalysisOutput): Promise<void> => {
    if (!domainEnabled()) return;
    const hosts = (output.summary.domain_threats ?? []).slice(0, 15).map((d) => d.host);
    if (hosts.length === 0) return;
    let verdicts: Record<string, import("./types").ReputationVerdict[]> = {};
    if (IS_TAURI) {
      const { invoke } = await import("@tauri-apps/api/core");
      verdicts = JSON.parse(await invoke<string>("domain_reputation_lookup", { hosts })) as typeof verdicts;
    } else {
      const proxy = getProxyUrl();
      const vtKey = getKey("virustotal");
      if (!proxy || !vtKey) return;
      const now = Math.floor(Date.now() / 1000);
      verdicts = await lookupDomainReputation(proxyHttp(proxy), hosts, vtKey, now);
    }
    if (Object.keys(verdicts).length === 0) return;
    await enrichAndCommit(output, verdicts, applyDomainReputationWasm);
  }, [enrichAndCommit]);

  // Open the domain consent gate or fire the domain reputation pass immediately.
  const triggerDomainReputationGate = useCallback((output: AnalysisOutput) => {
    if (!domainEnabled()) return;
    const domains = output.summary.domain_threats ?? [];
    if (domains.length === 0) return;
    if (domainConsentGiven()) {
      void runDomainReputation(output);
    } else {
      setDomainConsentPrompt({ output, domainCount: Math.min(15, domains.length) });
    }
  }, [runDomainReputation]);

  // Replace the active capture with a user-imported summary.json + flows.parquet (either may
  // be supplied). A summary turns it into a Recent entry; flows-only just updates the table.
  const handleReplaceData = useCallback(
    (next: { summary?: AnalysisOutput; flows?: FlowRow[] }) => {
      if (next.summary) {
        const out = next.summary;
        void applyCapture({
          summary: out,
          flows: next.flows,
          origin: "upload",
          source: null, // an imported summary/parquet has no original pcap to re-read
        }).then(() => {
          const key = out.source_sha256 ?? out.source_path;
          if (lastRepSourceRef.current !== key) {
            lastRepSourceRef.current = key;
            triggerReputationGate(out);
            triggerDomainReputationGate(out);
          }
        });
      } else if (next.flows) {
        setFlows({ status: "ready", rows: next.flows });
        setActiveSource(null); // swapped flows out of band — old source no longer matches
      }
    },
    [applyCapture, triggerReputationGate, triggerDomainReputationGate],
  );

  const handleNativeLoad = useCallback(async () => {
    const path = await openCaptureDialog();
    if (!path) return;
    setSummary({ status: "loading" });
    setFlows({ status: "loading", rows: [] });
    setTab("dashboard");
    try {
      const { summary: nextSummary, rows } = await analyzeViaTauri(path);
      await applyCapture({
        summary: nextSummary,
        flows: rows,
        path,
        fileName: basename(path),
        origin: "native",
        source: { kind: "path", path },
      });
      const key = nextSummary.source_sha256 ?? nextSummary.source_path;
      if (lastRepSourceRef.current !== key) {
        lastRepSourceRef.current = key;
        triggerReputationGate(nextSummary);
        triggerDomainReputationGate(nextSummary);
      }
    } catch (err: unknown) {
      const message = String((err as Error)?.message ?? err);
      setSummary({ status: "error", error: message });
      setFlows({ status: "error", rows: [], error: message });
    }
  }, [applyCapture, triggerReputationGate, triggerDomainReputationGate]);

  // Analyze a raw .pcap/.pcapng entirely in the browser via the WebAssembly engine. Errors
  // propagate to the load dialog (which keeps the current capture on screen on failure).
  const handleAnalyzePcap = useCallback(
    async (file: File) => {
      const bytes = await file.arrayBuffer();
      const { summary: nextSummary, rows } = await analyzeViaWasm(bytes, file.name);
      await applyCapture({
        summary: nextSummary,
        flows: rows,
        fileName: file.name,
        sizeBytes: file.size,
        origin: "wasm",
        // Retain the pcap bytes for in-browser packet extraction, but only under the size
        // cap so we don't pin huge captures in memory.
        source: bytes.byteLength <= MAX_RETAIN_BYTES ? { kind: "bytes", bytes } : null,
      });
      setTab("dashboard");
      const key = nextSummary.source_sha256 ?? nextSummary.source_path;
      if (lastRepSourceRef.current !== key) {
        lastRepSourceRef.current = key;
        triggerReputationGate(nextSummary);
        triggerDomainReputationGate(nextSummary);
      }
    },
    [applyCapture, triggerReputationGate, triggerDomainReputationGate],
  );

  // The "Load capture" affordance: native dialog on desktop, in-app drop dialog in browser.
  const handleRequestLoad = useCallback(() => {
    if (IS_TAURI) void handleNativeLoad();
    else setLoadDialogOpen(true);
  }, [handleNativeLoad]);

  // Open a recent capture: restore its cached stats instantly, plus cached flows if present.
  const handleSelectRecent = useCallback(async (entry: RecentEntry) => {
    setActiveId(entry.id);
    setSummary({ status: "ready", data: entry.summary });
    setTab("dashboard");
    setSelectedIncident(null);
    setActiveIp(null);
    // Recent entries restore cached stats only — we no longer hold the original pcap bytes,
    // so packet drill-down stays disabled until the capture is re-analyzed.
    setActiveSource(null);
    setFlows({ status: "loading", rows: [] });
    const cached = await getFlows(entry.id);
    setFlows({ status: "ready", rows: cached ?? [] });
  }, []);

  // Re-run the engine on the original file. Desktop re-analyzes in place from the stored
  // path; in the browser we no longer hold the bytes, so re-open the picker.
  const handleReanalyze = useCallback(
    async (entry: RecentEntry) => {
      if (entry.path && IS_TAURI) {
        setBusyId(entry.id);
        setActiveId(entry.id);
        setTab("dashboard");
        setSummary({ status: "loading" });
        setFlows({ status: "loading", rows: [] });
        try {
          const { summary: nextSummary, rows } = await analyzeViaTauri(entry.path);
          await applyCapture({
            summary: nextSummary,
            flows: rows,
            path: entry.path,
            fileName: entry.name,
            origin: "native",
            source: { kind: "path", path: entry.path },
          });
          const key = nextSummary.source_sha256 ?? nextSummary.source_path;
          if (lastRepSourceRef.current !== key) {
            lastRepSourceRef.current = key;
            triggerReputationGate(nextSummary);
            triggerDomainReputationGate(nextSummary);
          }
        } catch (err: unknown) {
          const message = String((err as Error)?.message ?? err);
          setSummary({ status: "error", error: message });
          setFlows({ status: "error", rows: [], error: message });
        } finally {
          setBusyId(null);
        }
      } else {
        setLoadDialogOpen(true);
      }
    },
    [applyCapture, triggerReputationGate, triggerDomainReputationGate],
  );

  const handleRemoveRecent = useCallback(
    (entry: RecentEntry) => {
      setRecent(removeRecent(entry.id));
      setActiveId((cur) => (cur === entry.id ? null : cur));
    },
    [],
  );

  const handleClearRecent = useCallback(() => {
    setRecent(clearRecent());
    setActiveId(null);
  }, []);

  const handleExport = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    const ai = await getAiSummary(captureKey(summary.data));
    return exportReport(summary.data, ai?.text);
  }, [summary]);

  const handleExportCsv = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return exportCsv(summary.data);
  }, [summary]);
  const handleExportStix = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return exportStix(summary.data);
  }, [summary]);
  const handleCopyCsv = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return copyCsv(summary.data);
  }, [summary]);
  const handleCopyStix = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return copyStix(summary.data);
  }, [summary]);
  const handleExportMisp = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return exportMisp(summary.data);
  }, [summary]);
  const handleCopyMisp = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return copyMisp(summary.data);
  }, [summary]);
  const handleExportCef = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return exportCef(summary.data);
  }, [summary]);
  const handleCopyCef = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return copyCef(summary.data);
  }, [summary]);

  const jumpToFlows = useCallback(
    (filter: { severity?: Severity; category?: string; ip?: string }) => {
      setFlowsFilter({ severity: filter.severity, category: filter.category, ip: filter.ip });
      setTab("flows");
    },
    [],
  );

  const openThreat = useCallback((ip: string) => {
    setActiveIp(ip);
    const inc = (summary.data?.summary.incidents ?? []).find((i) => i.host === ip);
    if (inc) { setSelectedIncident(inc); setTab("dashboard"); }
    else { jumpToFlows({ ip }); }
  }, [summary, jumpToFlows]);

  // Auto-dismiss the rule notice after a short delay.
  useEffect(() => {
    if (!ruleNotice) return;
    const t = window.setTimeout(() => setRuleNotice(null), 4000);
    return () => window.clearTimeout(t);
  }, [ruleNotice]);

  const applyRuleText = useCallback(async (text: string) => {
    if (summary.status !== "ready" || !summary.data || !packetsAvailable(activeSource)) return;
    const currentData = summary.data;
    const key = captureKey(currentData);
    // Reuse the per-capture base so re-loading replaces (not stacks) and reputation isn't clobbered.
    const base = pickRuleBase(ruleBaseRef, key, currentData);
    try {
      const res = await applyRules(text, base, activeSource);
      setSummary({ status: "ready", data: res.output });
      setRuleNotice(`Rules: ${res.loaded} loaded, ${res.skipped} skipped, ${res.matches} match${res.matches === 1 ? "" : "es"}`);
    } catch (e) {
      setRuleNotice(e instanceof Error ? e.message : "Failed to apply rules");
    }
  }, [summary, activeSource]);

  const loadRules = useCallback(async (file: File) => {
    const text = await file.text();
    saveRuleSet(file.name, text); // persist (non-fatal if it fails)
    await applyRuleText(text);
  }, [applyRuleText]);

  const applyRuleSet = useCallback((rs: RuleSet) => { void applyRuleText(rs.text); }, [applyRuleText]);

  return (
    <>
    {/* Hidden file input for "Load detection rules" — triggered via rulesInputRef.current.click() */}
    <input
      ref={rulesInputRef}
      type="file"
      accept=".rules,.txt"
      hidden
      onChange={(e) => {
        const f = e.target.files?.[0];
        if (f) void loadRules(f);
        e.target.value = "";
      }}
    />
    <AppShell
      activeTab={tab}
      onTabChange={setTab}
      compareActive={compareIds !== null}
      summary={summary}
      recentCount={recent.length}
      onReplaceData={handleReplaceData}
      onAnalyzePcap={handleAnalyzePcap}
      onRequestLoad={handleRequestLoad}
      loadDialogOpen={loadDialogOpen}
      onLoadDialogOpenChange={setLoadDialogOpen}
      onExport={handleExport}
      onExportCsv={handleExportCsv}
      onExportStix={handleExportStix}
      onCopyCsv={handleCopyCsv}
      onCopyStix={handleCopyStix}
      onExportMisp={handleExportMisp}
      onCopyMisp={handleCopyMisp}
      onExportCef={handleExportCef}
      onCopyCef={handleCopyCef}
      threats={summary.status === "ready" ? summary.data?.summary.ip_threats ?? [] : []}
      activeIp={activeIp}
      onSelectThreat={openThreat}
      collapsed={collapsed}
      onToggleCollapse={() => setCollapsed((c) => !c)}
      onOpenPalette={() => setPaletteOpen(true)}
      paletteOpen={paletteOpen}
      onPaletteOpenChange={setPaletteOpen}
      onOpenSettings={() => setSettingsOpen(true)}
      onOpenAiChat={summary.status === "ready" && summary.data ? () => setAiChatOpen(true) : undefined}
      onLoadRules={packetsAvailable(activeSource) ? () => rulesInputRef.current?.click() : undefined}
      rulesMenu={<RuleSetsMenu onLoadFile={() => rulesInputRef.current?.click()} onApply={applyRuleSet} disabled={!packetsAvailable(activeSource)} />}
    >
      {tab === "compare" ? (
        (() => {
          const [olderId, newerId] = compareIds ?? ["", ""];
          const older = recent.find((e) => e.id === olderId);
          const newer = recent.find((e) => e.id === newerId);
          const before = compareSwapped ? newer : older;
          const after = compareSwapped ? older : newer;
          return <CompareView before={before} after={after} onSwap={() => setCompareSwapped((s) => !s)} />;
        })()
      ) : tab === "flows" ? (
        <FlowsView state={flows} initialFilter={flowsFilter} activeSource={activeSource} />
      ) : tab === "recent" ? (
        <RecentView
          entries={recent}
          activeId={activeId}
          busyId={busyId}
          onOpen={(e) => void handleSelectRecent(e)}
          onReanalyze={(e) => void handleReanalyze(e)}
          onRemove={handleRemoveRecent}
          onClear={handleClearRecent}
          onLoadNew={handleRequestLoad}
          onCompare={startCompare}
        />
      ) : summary.status === "idle" ? (
        IS_TAURI ? (
          <EmptyState title="No capture loaded" />
        ) : (
          <LoadingState label="Loading summary…" />
        )
      ) : summary.status === "loading" ? (
        <LoadingState label="Loading summary…" />
      ) : summary.status === "error" ? (
        <ErrorState message={summary.error ?? "Failed to load summary"} />
      ) : (
        <Dashboard
          output={summary.data!}
          onJumpToFlows={jumpToFlows}
          selectedIncident={selectedIncident}
          onSelectIncident={setSelectedIncident}
          activeSource={activeSource}
        />
      )}
    </AppShell>
    {consentPrompt && (
      <ReputationConsent
        ipCount={consentPrompt.ipCount}
        providers={consentPrompt.providers}
        onProceed={() => {
          giveConsent();
          const out = consentPrompt.output;
          setConsentPrompt(null);
          void runReputation(out);
        }}
        onCancel={() => setConsentPrompt(null)}
      />
    )}
    {domainConsentPrompt && (
      <DomainConsent
        domainCount={domainConsentPrompt.domainCount}
        onProceed={() => {
          giveDomainConsent();
          const out = domainConsentPrompt.output;
          setDomainConsentPrompt(null);
          void runDomainReputation(out);
        }}
        onCancel={() => setDomainConsentPrompt(null)}
      />
    )}
    {settingsOpen && (
      <SettingsDialog onClose={() => setSettingsOpen(false)} />
    )}
    {summary.status === "ready" && summary.data && (
      <AiChatPanel open={aiChatOpen} onClose={() => setAiChatOpen(false)} output={summary.data} />
    )}
    {ruleNotice && (
      <div
        role="status"
        aria-live="polite"
        className="pointer-events-none fixed bottom-4 left-1/2 z-50 -translate-x-1/2 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-4 py-2 text-xs text-[var(--color-text-dim)] shadow-lg"
      >
        {ruleNotice}
      </div>
    )}
    </>
  );
}

export default App;
