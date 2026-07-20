import { useDialogA11y } from "../lib/useDialogA11y";
import { BTN_OUTLINE, BTN_PRIMARY, DIALOG_PANEL, OVERLAY_BACKDROP } from "./primitives";

/**
 * Consent gate for the two VirusTotal enrichment passes that send capture-derived indicators
 * offsite: SNI domains and carved-file SHA-256 hashes. One consent covers both — a hash discloses
 * strictly less than a domain. Counts are conditional so the copy stays accurate for any mix.
 */
export function DomainConsent({ domainCount, fileCount = 0, onProceed, onCancel }:
  { domainCount: number; fileCount?: number; onProceed: () => void; onCancel: () => void }) {
  const { ref, onKeyDown } = useDialogA11y(onCancel);

  const titleParts: string[] = [];
  if (domainCount > 0) titleParts.push(`${domainCount} domain${domainCount === 1 ? "" : "s"}`);
  if (fileCount > 0) titleParts.push(`${fileCount} file hash${fileCount === 1 ? "" : "es"}`);
  const subject = titleParts.join(" and ") || "indicators";

  const domainPhrase = domainCount > 0
    ? `the top ${domainCount} TLS SNI hostname${domainCount === 1 ? "" : "s"} this capture contacted`
    : "";
  const filePhrase = fileCount > 0
    ? `the SHA-256 hash${fileCount === 1 ? "" : "es"} of ${fileCount} carved file${fileCount === 1 ? "" : "s"}`
    : "";
  const sentence = [domainPhrase, filePhrase].filter(Boolean).join(", and ");
  const sentenceCap = sentence.charAt(0).toUpperCase() + sentence.slice(1);

  return (
    <div ref={ref} onKeyDown={onKeyDown} role="dialog" aria-modal="true" aria-label="VirusTotal reputation consent" className={`${OVERLAY_BACKDROP} z-50 flex items-center justify-center p-4`}>
      <div className={`${DIALOG_PANEL} w-full max-w-md text-[var(--color-text)]`}>
        <div className="border-b border-[var(--color-border)] px-5 py-4">
          <h2 className="text-sm font-medium">Send {subject} to VirusTotal?</h2>
        </div>
        <div className="px-5 py-4">
          <p className="text-xs text-[var(--color-text-dim)]">
            {sentenceCap} will be sent <strong>via PacketPilot's servers</strong> to VirusTotal to check
            reputation. Internal IPs, file contents, payloads, and the capture itself never leave this device.
          </p>
        </div>
        <div className="flex justify-end gap-2 border-t border-[var(--color-border)] px-5 py-3">
          <button type="button" className={BTN_OUTLINE} onClick={onCancel}>Cancel</button>
          <button type="button" className={BTN_PRIMARY} onClick={onProceed}>Proceed</button>
        </div>
      </div>
    </div>
  );
}
