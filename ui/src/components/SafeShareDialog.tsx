import { useMemo, useState } from "react";
import type { ActiveSource, AnalysisOutput, SanitizeManifest, SanitizeOptions } from "../types";
import { exportSanitized, type ExportResult } from "../lib/platform";
import { useDialogA11y } from "../lib/useDialogA11y";

/**
 * Safe Share — export a sanitized/anonymized copy of the active capture.
 *
 * Options panel over the engine's sanitize pass: payload policy, prefix
 * preservation, OUI preservation, and time shift. Everything runs locally
 * (native on desktop, WASM in the browser); a manifest sidecar records counts
 * and hashes, never original values. After a successful run the dialog shows
 * a summary of what was transformed.
 */
export function SafeShareDialog({
  source,
  summary,
  onClose,
  onResult,
}: {
  source: ActiveSource;
  summary: AnalysisOutput;
  onClose: () => void;
  onResult?: (res: ExportResult) => void;
}) {
  const { ref, onKeyDown } = useDialogA11y(onClose);
  const [payload, setPayload] = useState<"scrub" | "keep">("scrub");
  const [preservePrefix, setPreservePrefix] = useState(true);
  const [preserveOui, setPreserveOui] = useState(false);
  const [timeShift, setTimeShift] = useState(false);
  const [busy, setBusy] = useState(false);
  const [manifest, setManifest] = useState<SanitizeManifest | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Output container follows the source filename; .pcapng in → .pcapng out.
  const format = useMemo<"pcap" | "pcapng">(
    () => (summary.source_path.toLowerCase().includes(".pcapng") ? "pcapng" : "pcap"),
    [summary.source_path],
  );

  const run = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      const options: SanitizeOptions = {
        payload,
        preserve_prefix: preservePrefix,
        preserve_oui: preserveOui,
        redact_l7: true,
        // A fixed -30d shift keeps relative timing intact while decoupling the
        // capture from externally-correlatable wall-clock times.
        time_shift_secs: timeShift ? -30 * 24 * 3600 : 0,
        format,
      };
      const res = await exportSanitized(source, summary, options);
      if (res.ok && res.manifest) {
        setManifest(res.manifest);
        onResult?.(res);
      } else if (res.message) {
        setError(res.message);
      } else {
        onClose(); // save dialog cancelled
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const checkbox =
    "h-3.5 w-3.5 accent-[var(--color-accent-deep)]";
  const label = "flex items-start gap-2 text-xs text-[var(--color-text)]";
  const hint = "block text-[11px] text-[var(--color-text-dim)]";

  return (
    <div
      ref={ref}
      onKeyDown={onKeyDown}
      role="dialog"
      aria-modal="true"
      aria-label="Export sanitized capture"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
    >
      <div className="w-full max-w-md rounded-[var(--r-card)] border border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text)] shadow-[var(--sh-float)]">
        <div className="border-b border-[var(--color-border)] px-5 py-4">
          <h2 className="text-sm font-medium">Export sanitized capture (Safe Share)</h2>
          <p className="mt-1 text-[11px] text-[var(--color-text-dim)]">
            Writes an anonymized copy you can share with vendors, CERTs, or other teams.
            Addresses become stable pseudonyms, sensitive fields are redacted, checksums are
            recomputed, and a manifest records what changed — all locally; the capture and
            the mapping key never leave this device.
          </p>
        </div>

        {manifest ? (
          <div className="px-5 py-4">
            <p className="text-xs font-medium">Done — {manifest.counts.packets_written.toLocaleString()} packets sanitized.</p>
            <ul className="mt-2 space-y-1 text-[11px] text-[var(--color-text-dim)]">
              <li>{manifest.counts.unique_ipv4 + manifest.counts.unique_ipv6} IP and {manifest.counts.unique_macs} MAC pseudonyms assigned</li>
              <li>
                {manifest.counts.dns_names_redacted} DNS names, {manifest.counts.http_fields_redacted} HTTP fields,{" "}
                {manifest.counts.tls_snis_redacted} TLS SNI, {manifest.counts.credentials_redacted} credentials redacted
              </li>
              <li>{manifest.counts.payload_bytes_scrubbed.toLocaleString()} payload bytes scrubbed</li>
              <li className="break-all">output sha256 {manifest.output_sha256}</li>
            </ul>
          </div>
        ) : (
          <div className="space-y-3 px-5 py-4">
            <label className={label}>
              <input
                type="radio"
                name="ss-payload"
                className={checkbox}
                checked={payload === "scrub"}
                onChange={() => setPayload("scrub")}
              />
              <span>
                Scrub payloads <span className="text-[var(--color-text-dim)]">(recommended)</span>
                <span className={hint}>Zero every application payload byte — only headers, sizes, and timing remain.</span>
              </span>
            </label>
            <label className={label}>
              <input
                type="radio"
                name="ss-payload"
                className={checkbox}
                checked={payload === "keep"}
                onChange={() => setPayload("keep")}
              />
              <span>
                Keep payloads, redact sensitive fields
                <span className={hint}>
                  Keeps application data for deeper analysis; DNS names, HTTP host/URL/credentials,
                  TLS SNI, and cleartext logins are replaced with stable tokens. Unrecognized payloads
                  are kept as-is.
                </span>
              </span>
            </label>
            <label className={label}>
              <input
                type="checkbox"
                className={checkbox}
                checked={preservePrefix}
                onChange={(e) => setPreservePrefix(e.target.checked)}
              />
              <span>
                Preserve subnet structure
                <span className={hint}>Hosts of one subnet stay grouped in a pseudonymous subnet (Crypto-PAn-style mapping).</span>
              </span>
            </label>
            <label className={label}>
              <input
                type="checkbox"
                className={checkbox}
                checked={preserveOui}
                onChange={(e) => setPreserveOui(e.target.checked)}
              />
              <span>
                Keep MAC vendor prefixes (OUI)
                <span className={hint}>Reveals NIC vendors but keeps device-type context for the recipient.</span>
              </span>
            </label>
            <label className={label}>
              <input
                type="checkbox"
                className={checkbox}
                checked={timeShift}
                onChange={(e) => setTimeShift(e.target.checked)}
              />
              <span>
                Shift timestamps
                <span className={hint}>Moves the whole capture 30 days into the past (relative timing intact) to blunt correlation with external logs.</span>
              </span>
            </label>
            {error && <p className="text-[11px] text-[var(--color-danger,#f87171)]">{error}</p>}
          </div>
        )}

        <div className="flex justify-end gap-2 border-t border-[var(--color-border)] px-5 py-3">
          <button
            type="button"
            className="rounded-[var(--r-micro)] border border-[var(--color-border)] bg-transparent px-3 py-1.5 text-xs font-medium text-[var(--color-text-dim)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
            onClick={onClose}
          >
            {manifest ? "Close" : "Cancel"}
          </button>
          {!manifest && (
            <button
              type="button"
              className="rounded-[var(--r-micro)] bg-[var(--color-accent-deep)] px-3 py-1.5 text-xs font-medium text-[var(--color-on-accent)] transition-opacity hover:opacity-90 disabled:opacity-60"
              onClick={() => void run()}
              disabled={busy}
            >
              {busy ? "Sanitizing…" : "Export"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
