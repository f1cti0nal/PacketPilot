import { useCallback, useId, useRef, useState, type DragEvent } from "react";
import { AlertTriangle, CheckCircle2, Loader2, Upload, X } from "lucide-react";
import type { AnalysisOutput, FlowRow } from "../../types";
import { loadFlows } from "../../lib/data";
import { isCaptureFile } from "../../lib/wasmEngine";
import { compactNumber, humanBytes } from "../../lib/format";
import { cn } from "../../lib/cn";

type LoadStatus =
  | { phase: "idle" }
  | { phase: "loading"; note: string }
  | { phase: "ready"; summary?: AnalysisOutput; flows?: FlowRow[]; fileNames: string[] }
  | { phase: "error"; message: string };

export function LoadCaptureDialog({
  onReplaceData,
  onAnalyzePcap,
  onClose,
}: {
  onReplaceData: (next: { summary?: AnalysisOutput; flows?: FlowRow[] }) => void;
  onAnalyzePcap: (file: File) => Promise<void>;
  onClose: () => void;
}) {
  const [status, setStatus] = useState<LoadStatus>({ phase: "idle" });
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const titleId = useId();

  const handleFiles = useCallback(
    async (files: FileList | null) => {
      if (!files || files.length === 0) return;
      const list = Array.from(files);

      // A raw capture takes priority: analyze it in-browser via the wasm engine, then close.
      const captureFile = list.find((f) => isCaptureFile(f.name));
      if (captureFile) {
        setStatus({
          phase: "loading",
          note: `Analyzing ${captureFile.name}…`,
        });
        try {
          await onAnalyzePcap(captureFile);
          onClose();
        } catch (err: unknown) {
          setStatus({
            phase: "error",
            message: String((err as Error)?.message ?? err),
          });
        }
        return;
      }

      const summaryFile = list.find((f) => f.name.toLowerCase().endsWith(".json"));
      const flowsFile = list.find((f) =>
        f.name.toLowerCase().endsWith(".parquet"),
      );
      if (!summaryFile && !flowsFile) {
        setStatus({
          phase: "error",
          message:
            "Drop a .pcap/.pcapng capture, or a summary.json and/or flows.parquet.",
        });
        return;
      }
      setStatus({ phase: "loading", note: "Parsing capture…" });
      try {
        let summary: AnalysisOutput | undefined;
        let flows: FlowRow[] | undefined;
        if (summaryFile) {
          summary = JSON.parse(await summaryFile.text()) as AnalysisOutput;
        }
        if (flowsFile) {
          const buf = await flowsFile.arrayBuffer();
          flows = await loadFlows(buf);
        }
        // Lift the parsed capture up to App state, replacing the active dataset.
        onReplaceData({ summary, flows });
        setStatus({
          phase: "ready",
          summary,
          flows,
          fileNames: list.map((f) => f.name),
        });
      } catch (err: unknown) {
        setStatus({
          phase: "error",
          message: String((err as Error)?.message ?? err),
        });
      }
    },
    [onReplaceData, onAnalyzePcap, onClose],
  );

  const onDrop = useCallback(
    (e: DragEvent<HTMLDivElement>) => {
      e.preventDefault();
      setDragging(false);
      void handleFiles(e.dataTransfer.files);
    },
    [handleFiles],
  );

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      onClick={onClose}
    >
      <div
        className="w-full max-w-md rounded-xl border border-border bg-surface shadow-2xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2 id={titleId} className="text-sm font-semibold">
            Load capture
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-md p-1 text-[var(--color-text-dim)] transition-colors hover:bg-surface-2 hover:text-[var(--color-text)]"
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        </div>

        <div className="p-4">
          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
            onClick={() => inputRef.current?.click()}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => {
              if (e.key === "Enter" || e.key === " ") inputRef.current?.click();
            }}
            className={cn(
              "flex cursor-pointer flex-col items-center justify-center gap-2 rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors",
              dragging
                ? "border-[var(--color-accent)] bg-surface-2"
                : "border-border hover:border-[var(--color-text-faint)]",
            )}
          >
            <Upload
              className="h-7 w-7 text-[var(--color-text-faint)]"
              aria-hidden
            />
            <div className="text-sm text-[var(--color-text)]">
              Drag &amp; drop, or click to browse
            </div>
            <div className="text-xs text-[var(--color-text-dim)]">
              <span className="font-mono-num">.pcap</span> /{" "}
              <span className="font-mono-num">.pcapng</span> — analyzed in your browser
            </div>
            <div className="text-[11px] text-[var(--color-text-faint)]">
              or a <span className="font-mono-num">summary.json</span> +{" "}
              <span className="font-mono-num">flows.parquet</span> export
            </div>
            <input
              ref={inputRef}
              type="file"
              multiple
              accept=".pcap,.pcapng,.cap,.json,.parquet,application/json"
              className="hidden"
              onChange={(e) => void handleFiles(e.target.files)}
            />
          </div>

          <div className="mt-3 min-h-[1.25rem] text-xs" aria-live="polite">
            {status.phase === "loading" && (
              <span className="inline-flex items-center gap-1.5 text-[var(--color-text-dim)]">
                <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden />
                {status.note}
              </span>
            )}
            {status.phase === "error" && (
              <span className="inline-flex items-center gap-1.5 text-sev-critical">
                <AlertTriangle className="h-3.5 w-3.5" aria-hidden />
                {status.message}
              </span>
            )}
            {status.phase === "ready" && (
              <span className="inline-flex items-center gap-1.5 text-sev-info">
                <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
                Loaded {loadedSummaryLabel(status)}
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function loadedSummaryLabel(s: Extract<LoadStatus, { phase: "ready" }>): string {
  const parts: string[] = [];
  if (s.summary) {
    parts.push(
      `${compactNumber(s.summary.summary.total_packets)} pkts`,
      humanBytes(s.summary.summary.total_bytes),
    );
  }
  if (s.flows) parts.push(`${compactNumber(s.flows.length)} flows`);
  return parts.length ? parts.join(" · ") : s.fileNames.join(", ");
}

export default LoadCaptureDialog;
