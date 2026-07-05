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
  updateRecentSummary,
  removeRecent,
  clearRecent,
} from "./lib/recent";
import { onStorageScopeChange } from "./lib/storageScope";
import { AppShell } from "./components/layout/AppShell";
import { useTheme } from "./cockpit/ThemeToggle";
import { LoadingState } from "./components/state/LoadingState";
import { ErrorState } from "./components/state/ErrorState";
import { ErrorBoundary } from "./components/state/ErrorBoundary";
import { Dashboard } from "./components/Dashboard";
import { FlowsView } from "./views/FlowsView";
import { FindingsView } from "./views/FindingsView";
import { ThreatsView } from "./views/ThreatsView";
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
  exportSigma,
  copyCsv,
  copyStix,
  copyMisp,
  copyCef,
  copySigma,
  applyRules,
} from "./lib/platform";
import { packetsAvailable } from "./lib/packets";
import { analyzeViaWasm, applyReputationWasm, applyDomainReputationWasm } from "./lib/wasmEngine";
import { HomeView } from "./components/home/HomeView";
import {
  consentGiven,
  giveConsent,
  domainConsentGiven,
  giveDomainConsent,
  fileConsentGiven,
  giveFileConsent,
} from "./lib/reputation/settings";
import { lookupReputation, lookupDomainReputation, lookupFileReputation } from "./lib/reputation/orchestrator";
import { applyFileReputation } from "./lib/reputation/applyFile";
import { edgeRepHttp } from "./lib/reputation/edgeHttp";
import { ReputationConsent } from "./cockpit/ReputationConsent";
import { DomainConsent } from "./cockpit/DomainConsent";
import { AiChatPanel } from "./cockpit/AiChatPanel";
import { getAiSummary, captureKey } from "./lib/ai/cache";
import { pickRuleBase } from "./lib/ruleBase";
import { saveRuleSet, type RuleSet } from "./lib/ruleSets";
import { RuleSetsMenu } from "./components/flows/RuleSetsMenu";
import { IocDialog } from "./cockpit/IocDialog";
import { matchIocs, parseIocs } from "./lib/ioc/ioc";
import { useSession } from "./auth/useSession";
import { AccountMenu } from "./auth/AccountMenu";
import { DemoBanner } from "./auth/DemoBanner";
import { reconcileAfterCheckout } from "./auth/billing";
import { trackPageView } from "./lib/analytics/track";
import { gaPageView } from "./lib/analytics/ga";
import { useFeatureFlags } from "./lib/features/useFeatureFlags";
import { useAppSettings } from "./lib/settings/useAppSettings";
import { AnnouncementBanner } from "./cockpit/AnnouncementBanner";

const repCaptureKey = (o: AnalysisOutput): string | undefined => o.source_sha256 ?? o.source_path;

export interface FlowsInitialFilter {
  severity?: Severity;
  category?: string;
  proto?: number;
  ip?: string;
  /** Free-text query to seed the filter box (e.g. a port, HTTP host, or protocol from a card). */
  query?: string;
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

export function App({ demo = false }: { demo?: boolean } = {}) {
  // Re-render the whole tree on theme toggle so sevColor()'s baked literals refresh: it
  // resolves a CSS var to a literal hex at render time (for SVG/recharts), so without a
  // re-render severity colours would stay the previous theme's palette after a toggle.
  useTheme();
  const session = useSession();
  const appSettings = useAppSettings();
  const { announcement_banner } = appSettings;
  const rep = appSettings.rep;
  const plan = session.status === "authed" ? session.profile.plan : "free";
  const { gate } = useFeatureFlags(session.status === "authed", plan);
  const aiGate = gate("ai_assist");
  const pcapGate = gate("pcap_export");
  const compareGate = gate("multi_capture_diff");
  // Reputation enrichment (IP/domain/file) is a Pro feature: fold the plan gate into the master
  // switch so EVERY reputation path (incl. the consent prompt) stays off for free/hosted users.
  // Offline/self-host (DEFAULTS, plan_gate null) keep it on; the reputation-proxy enforces it too.
  const repEnabled = rep.enabled && gate("reputation") === "on";
  // Saved rule-set LIBRARY (persist + reuse across captures) is Pro. One-off "load & apply a
  // .rules file" (rule import) stays free — only the save side-effect + saved list are gated.
  const savedRulesAllowed = gate("saved_rules") === "on";
  const aiOn = session.status === "authed" && appSettings.ai.enabled && aiGate === "on";
  const aiModel = appSettings.ai.model;

  // After returning from Stripe Checkout, refresh the session so the upgraded plan shows.
  useEffect(() => {
    void reconcileAfterCheckout();
  }, []);

  // Cold traffic from the SEO/marketing pages can deep-link to /app?sample=1 to drop straight
  // into a live demo (no file needed). Load the bundled sample once, then strip the param.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const params = new URLSearchParams(window.location.search);
    if (params.get("sample") !== "1") return;
    loadSample();
    params.delete("sample");
    const qs = params.toString();
    window.history.replaceState({}, "", window.location.pathname + (qs ? `?${qs}` : ""));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const [tab, setTab] = useState<TabId>("dashboard");
  useEffect(() => {
    trackPageView(`/app#${tab}`);
    gaPageView(`/app#${tab}`);
  }, [tab]);
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
  // If the signed-in account changes while App is mounted (sign in/out/switch in place), reload
  // Recent under the new account's namespace and drop any in-view capture from the previous one.
  // The primary fix is that useSession sets the scope before App mounts (so the initial read above
  // is already correct); this keeps a live switch consistent too.
  useEffect(
    () =>
      onStorageScopeChange(() => {
        setRecent(listRecent());
        setActiveId(null);
      }),
    [],
  );
  const [loadDialogOpen, setLoadDialogOpen] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [collapsed, setCollapsed] = useState(false);
  const [activeIp, setActiveIp] = useState<string | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [aiChatOpen, setAiChatOpen] = useState(false);
  // Consent prompt state: set when a newly-loaded capture has public IPs but consent hasn't
  // been given yet; cleared when the user proceeds or cancels.
  const [consentPrompt, setConsentPrompt] = useState<{ output: AnalysisOutput; ipCount: number; providers: string[] } | null>(null);
  // Domain consent prompt: set when a capture has domain threats but domain consent hasn't been given.
  const [domainConsentPrompt, setDomainConsentPrompt] = useState<{ output: AnalysisOutput; domainCount: number; fileCount: number } | null>(null);
  // Tracks the source identity of the last capture we ran (or offered to run) the reputation
  // pass on, preventing double-triggers when summary state re-renders.
  const lastRepSourceRef = useRef<string | null>(null);
  // The freshest "ready" summary, so each reputation pass enriches the latest data (not a stale
  // snapshot); a chain serializes the IP and domain commits so they compose, never clobber.
  const summaryDataRef = useRef<AnalysisOutput | null>(null);
  const repChainRef = useRef<Promise<void>>(Promise.resolve());
  // Mirror of activeId for use inside enrichAndCommit (which holds no React deps): identifies the
  // Recent entry to write the reputation-enriched summary back to, so a reopen restores it.
  const activeIdRef = useRef<string | null>(null);

  // Rule-loading: base snapshot prevents re-stacking (each reload applies over the original
  // reputation-enriched summary, not the previously-rules-augmented one).
  const ruleBaseRef = useRef<{ key: string; data: AnalysisOutput } | null>(null);
  const [ruleNotice, setRuleNotice] = useState<string | null>(null);
  const rulesInputRef = useRef<HTMLInputElement | null>(null);
  const [iocDialogOpen, setIocDialogOpen] = useState(false);

  // The app no longer auto-loads the bundled sample — launch lands on the Home surface
  // (upload-first hero for new visitors, workspace overview for returning ones). The sample
  // is now an opt-in preview, loaded on demand below WITHOUT recording to Recent, so it stays
  // a pure demo and never masquerades as the user's own capture history.
  const loadSample = useCallback(() => {
    setActiveId(null);
    setActiveSource(null); // the bundled sample has no re-extractable source
    setSelectedIncident(null);
    setActiveIp(null);
    setTab("dashboard");

    setSummary({ status: "loading" });
    loadSummary(SUMMARY_URL)
      .then((data) => setSummary({ status: "ready", data }))
      .catch((err: unknown) =>
        setSummary({ status: "error", error: String((err as Error)?.message ?? err) }),
      );

    setFlows({ status: "loading", rows: [] });
    loadFlows(FLOWS_URL)
      .then((rows) => setFlows({ status: "ready", rows }))
      .catch((err: unknown) =>
        setFlows({ status: "error", rows: [], error: String((err as Error)?.message ?? err) }),
      );
  }, []);

  // Keep activeIdRef in sync so enrichAndCommit can persist back to the right Recent entry.
  useEffect(() => {
    activeIdRef.current = activeId;
  }, [activeId]);

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
      const targetKey = repCaptureKey(base);
      const run = repChainRef.current.then(async () => {
        // The user may have switched captures while this pass was queued/awaiting.
        // Compose onto the live summary ONLY if it is still the same capture; otherwise
        // drop the pass entirely (neither enrich nor commit) so capture A's late-resolving
        // lookup can never overwrite capture B's on-screen summary.
        const before = summaryDataRef.current;
        if (!before || repCaptureKey(before) !== targetKey) return;
        const enriched = await apply(JSON.stringify(before), verdicts);
        const after = summaryDataRef.current;
        if (!after || repCaptureKey(after) !== targetKey) return;
        summaryDataRef.current = enriched;
        setSummary({ status: "ready", data: enriched });
        // Persist the enriched summary back to its Recent entry so reopening restores it
        // (with reputation chips) instead of re-querying the providers. The active entry IS
        // this capture — the same-key guards above guarantee we didn't switch away.
        const id = activeIdRef.current;
        if (id) setRecent(updateRecentSummary(id, enriched));
      });
      repChainRef.current = run.catch(() => {});
      return run;
    },
    [],
  );

  // Perform the reputation lookup and apply enriched results to the current summary IN PLACE.
  // Does NOT call applyCapture again — that would re-record to Recent and reset activeSource.
  const runReputation = useCallback(async (output: AnalysisOutput): Promise<void> => {
    if (session.status !== "authed" || !repEnabled) return;
    const ips = (output.summary.ip_threats ?? [])
      .filter((t) => t.ip_class === "public")
      .map((t) => t.ip);
    if (ips.length === 0) return;

    const now = Math.floor(Date.now() / 1000);
    const verdicts = await lookupReputation(edgeRepHttp(), ips, rep.providers, now);

    if (Object.keys(verdicts).length === 0) return;
    await enrichAndCommit(output, verdicts, applyReputationWasm);
  }, [session.status, repEnabled, rep.providers, enrichAndCommit]);

  // Open the consent gate or fire the reputation pass immediately, depending on whether
  // consent has already been given. Should be called once per new capture (after applyCapture).
  const triggerReputationGate = useCallback((output: AnalysisOutput) => {
    if (!repEnabled) return;
    const publicIps = (output.summary.ip_threats ?? []).filter((t) => t.ip_class === "public");
    if (publicIps.length === 0) return;
    if (consentGiven()) {
      void runReputation(output);
    } else {
      setConsentPrompt({ output, ipCount: publicIps.length, providers: rep.providers });
    }
  }, [repEnabled, rep.providers, runReputation]);

  // Perform domain reputation lookup and apply enriched results to the current summary IN PLACE.
  // Login + master-switch gates are stated here (not just relied on downstream), matching runReputation.
  const runDomainReputation = useCallback(async (output: AnalysisOutput): Promise<void> => {
    if (session.status !== "authed" || !repEnabled || !rep.domain_enabled || !rep.providers.includes("virustotal")) return;
    const hosts = (output.summary.domain_threats ?? []).slice(0, 15).map((d) => d.host);
    if (hosts.length === 0) return;
    const now = Math.floor(Date.now() / 1000);
    const verdicts = await lookupDomainReputation(edgeRepHttp(), hosts, now);
    if (Object.keys(verdicts).length === 0) return;
    await enrichAndCommit(output, verdicts, applyDomainReputationWasm);
  }, [session.status, repEnabled, rep.domain_enabled, rep.providers, enrichAndCommit]);

  // Perform file-hash reputation lookup (VirusTotal only) and apply IN PLACE. Composed entirely in
  // TS (applyFileReputation) since carved-file verdicts are display-only — no engine/WASM rebuild.
  const runFileReputation = useCallback(async (output: AnalysisOutput): Promise<void> => {
    if (session.status !== "authed" || !repEnabled || !rep.file_enabled || !rep.providers.includes("virustotal")) return;
    const hashes = (output.summary.carved_files ?? []).slice(0, 15).map((f) => f.sha256);
    if (hashes.length === 0) return;
    const now = Math.floor(Date.now() / 1000);
    const verdicts = await lookupFileReputation(edgeRepHttp(), hashes, now);
    if (Object.keys(verdicts).length === 0) return;
    await enrichAndCommit(output, verdicts, applyFileReputation);
  }, [session.status, repEnabled, rep.file_enabled, rep.providers, enrichAndCommit]);

  // Gate the two VirusTotal enrichment passes that send capture-derived indicators offsite — SNI
  // domains and carved-file SHA-256 hashes. These are DISTINCT indicator classes with SEPARATE
  // consent flags: a domain-only "Proceed" must never silently authorize sending file hashes (and
  // vice-versa). Whatever still needs consent is shown in the dialog and authorized only on Proceed.
  const triggerDomainReputationGate = useCallback((output: AnalysisOutput) => {
    const vt = repEnabled && rep.providers.includes("virustotal");
    const domainCount = vt && rep.domain_enabled ? (output.summary.domain_threats ?? []).length : 0;
    const fileCount = vt && rep.file_enabled ? (output.summary.carved_files ?? []).length : 0;
    if (domainCount === 0 && fileCount === 0) return;
    const needDomainConsent = domainCount > 0 && !domainConsentGiven();
    const needFileConsent = fileCount > 0 && !fileConsentGiven();
    // Already-consented passes fire immediately.
    if (domainCount > 0 && !needDomainConsent) void runDomainReputation(output);
    if (fileCount > 0 && !needFileConsent) void runFileReputation(output);
    // Prompt only for what still needs consent — the dialog discloses exactly those indicators.
    if (needDomainConsent || needFileConsent) {
      setDomainConsentPrompt({
        output,
        domainCount: needDomainConsent ? Math.min(15, domainCount) : 0,
        fileCount: needFileConsent ? Math.min(15, fileCount) : 0,
      });
    }
  }, [repEnabled, rep.domain_enabled, rep.file_enabled, rep.providers, runDomainReputation, runFileReputation]);

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
      // analyzeViaWasm runs in a Web Worker and TRANSFERS `bytes` away (so the heavy analysis can't
      // freeze the UI). Re-read the File to retain a copy for in-browser packet extraction — only
      // under the size cap, so we never pin a huge capture in memory.
      const retained = file.size <= MAX_RETAIN_BYTES ? await file.arrayBuffer() : null;
      await applyCapture({
        summary: nextSummary,
        flows: rows,
        fileName: file.name,
        sizeBytes: file.size,
        origin: "wasm",
        source: retained ? { kind: "bytes", bytes: retained } : null,
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
          // Re-analyze is an explicit "redo" — always re-run reputation (refreshing the chips
          // and the persisted summary), even if this source was already enriched this session.
          // Unlike the load paths, the lastRepSourceRef de-dup must NOT suppress it here.
          lastRepSourceRef.current = nextSummary.source_sha256 ?? nextSummary.source_path;
          triggerReputationGate(nextSummary);
          triggerDomainReputationGate(nextSummary);
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

  // Return to the Home overview: unload the active capture (it stays cached in Recent, so
  // reopening is instant). Non-destructive — just resets the view to the idle/Home branch.
  const goHome = useCallback(() => {
    setSummary({ status: "idle" });
    setFlows({ status: "idle", rows: [] });
    setActiveId(null);
    setActiveSource(null);
    setSelectedIncident(null);
    setActiveIp(null);
    setTab("dashboard");
  }, []);

  const handleExport = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    const ai = aiOn ? await getAiSummary(captureKey(summary.data)) : null;
    // Free-tier exports carry a PacketPilot attribution (a growth loop); Pro removes it.
    return exportReport(summary.data, ai?.text, { brand: plan !== "pro" });
  }, [summary, aiOn, plan]);

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
  const handleExportSigma = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return exportSigma(summary.data);
  }, [summary]);
  const handleCopySigma = useCallback(async () => {
    if (summary.status !== "ready" || !summary.data) return undefined;
    return copySigma(summary.data);
  }, [summary]);

  const jumpToFlows = useCallback(
    (filter: { severity?: Severity; category?: string; ip?: string; query?: string }) => {
      setFlowsFilter({
        severity: filter.severity,
        category: filter.category,
        ip: filter.ip,
        query: filter.query,
      });
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
    if (savedRulesAllowed) saveRuleSet(file.name, text); // persist is Pro; free users still apply one-off
    await applyRuleText(text);
  }, [applyRuleText, savedRulesAllowed]);

  const applyRuleSet = useCallback((rs: RuleSet) => { void applyRuleText(rs.text); }, [applyRuleText]);

  // Match a user-supplied IOC list against the loaded capture's extracted indicators. Runs over
  // the computed summary (no packets, no network), composing `ioc_match` findings — so it works on
  // any ready capture, including the sample. Queued on the SAME repChainRef the reputation passes
  // use and reads the freshest summaryDataRef, so an in-flight reputation commit can neither clobber
  // the ioc_match findings nor be clobbered by them (both serialize through one chain).
  const applyIocs = useCallback((text: string) => {
    if (summary.status !== "ready" || !summary.data) return;
    const iocs = parseIocs(text);
    const run = repChainRef.current.then(() => {
      const cur = summaryDataRef.current;
      if (!cur) return;
      const { output, matches } = matchIocs(cur, iocs);
      summaryDataRef.current = output;
      setSummary({ status: "ready", data: output });
      setRuleNotice(`IOCs: ${iocs.count} loaded, ${matches} match${matches === 1 ? "" : "es"}`);
    });
    repChainRef.current = run.catch(() => {});
  }, [summary]);

  return (
    <>
    <AnnouncementBanner banner={announcement_banner} />
    {/* Public-demo nudge: only when running the anonymous sample (AppGate passes `demo`) and the
        visitor isn't already signed in. */}
    {demo && session.status !== "authed" && <DemoBanner />}
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
      onGoHome={goHome}
      compareActive={compareIds !== null && compareGate === "on"}
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
      onExportSigma={handleExportSigma}
      onCopySigma={handleCopySigma}
      threats={summary.status === "ready" ? summary.data?.summary.ip_threats ?? [] : []}
      onSelectThreat={openThreat}
      collapsed={collapsed}
      onToggleCollapse={() => setCollapsed((c) => !c)}
      onOpenPalette={() => setPaletteOpen(true)}
      paletteOpen={paletteOpen}
      onPaletteOpenChange={setPaletteOpen}
      onOpenAiChat={aiOn && summary.status === "ready" && summary.data ? () => setAiChatOpen(true) : undefined}
      onLoadRules={packetsAvailable(activeSource) ? () => rulesInputRef.current?.click() : undefined}
      onMatchIocs={summary.status === "ready" && summary.data ? () => setIocDialogOpen(true) : undefined}
      rulesMenu={<RuleSetsMenu onLoadFile={() => rulesInputRef.current?.click()} onApply={applyRuleSet} disabled={!packetsAvailable(activeSource)} canSave={savedRulesAllowed} />}
      accountMenu={<AccountMenu session={session} />}
    >
      <ErrorBoundary resetKey={`${activeId ?? ""}:${tab}`}>
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
      ) : tab === "findings" ? (
        <FindingsView
          findings={summary.status === "ready" ? summary.data?.summary.findings ?? [] : []}
          onJumpToFlows={jumpToFlows}
        />
      ) : tab === "threats" ? (
        <ThreatsView
          threats={summary.status === "ready" ? summary.data?.summary.ip_threats ?? [] : []}
          activeIp={activeIp}
          onSelect={openThreat}
        />
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
          onCompare={compareGate === "on" ? startCompare : undefined}
        />
      ) : summary.status === "idle" ? (
        <HomeView
          recent={recent}
          activeId={activeId}
          onOpen={(e) => void handleSelectRecent(e)}
          onLoadNew={handleRequestLoad}
          onLoadSample={loadSample}
          onCompare={compareGate === "on" ? startCompare : undefined}
          onViewAll={() => setTab("recent")}
          sampleAvailable={!IS_TAURI}
        />
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
          aiGate={aiOn ? "on" : aiGate === "upsell" ? "upsell" : "off"}
          aiModel={aiModel}
          pcapExport={pcapGate === "on"}
        />
      )}
      </ErrorBoundary>
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
        fileCount={domainConsentPrompt.fileCount}
        onProceed={() => {
          const { output: out, domainCount: dc, fileCount: fc } = domainConsentPrompt;
          setDomainConsentPrompt(null);
          // Authorize + run ONLY the indicator classes the dialog actually disclosed.
          if (dc > 0) { giveDomainConsent(); void runDomainReputation(out); }
          if (fc > 0) { giveFileConsent(); void runFileReputation(out); }
        }}
        onCancel={() => setDomainConsentPrompt(null)}
      />
    )}
    {summary.status === "ready" && summary.data && (
      <AiChatPanel open={aiChatOpen} onClose={() => setAiChatOpen(false)} output={summary.data} model={aiModel} />
    )}
    {iocDialogOpen && (
      <IocDialog onMatch={applyIocs} onClose={() => setIocDialogOpen(false)} />
    )}
    {ruleNotice && (
      <div
        role="status"
        aria-live="polite"
        className="pointer-events-none fixed bottom-4 left-1/2 z-50 -translate-x-1/2 rounded-[var(--r-tile)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-4 py-2 text-xs text-[var(--color-text-dim)]"
      >
        {ruleNotice}
      </div>
    )}
    </>
  );
}

export default App;
