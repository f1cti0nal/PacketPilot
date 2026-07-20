import { useCallback, useId, useMemo, useRef, useState } from "react";
import { Fingerprint, Upload, X } from "lucide-react";
import { parseIocs } from "../lib/ioc/ioc";
import { useDialogA11y } from "../lib/useDialogA11y";
import { BTN_OUTLINE, BTN_PRIMARY, DIALOG_PANEL, INPUT_BASE, OVERLAY_BACKDROP } from "./primitives";

/**
 * Paste/upload an IOC list and match it against the loaded capture — entirely in the browser.
 * Parsing previews the indicator counts live; Match hands the raw text up to App, which runs
 * matchIocs() over the current summary and surfaces `ioc_match` findings.
 */
export function IocDialog({
  onMatch,
  onClose,
}: {
  onMatch: (text: string) => void;
  onClose: () => void;
}) {
  const [text, setText] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);
  const titleId = useId();
  const { ref: dialogRef, onKeyDown } = useDialogA11y(onClose);
  const parsed = useMemo(() => parseIocs(text), [text]);

  const loadFile = useCallback(async (file: File | undefined) => {
    if (!file) return;
    const content = await file.text();
    setText((prev) => (prev.trim() ? `${prev.replace(/\s+$/, "")}\n${content}` : content));
  }, []);

  const submit = useCallback(() => {
    if (parsed.count === 0) return;
    onMatch(text);
    onClose();
  }, [parsed.count, text, onMatch, onClose]);

  return (
    <div
      ref={dialogRef}
      onKeyDown={onKeyDown}
      className={`${OVERLAY_BACKDROP} z-50 flex items-center justify-center p-4`}
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      onClick={onClose}
    >
      <div
        className={`${DIALOG_PANEL} w-full max-w-md`}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <h2 id={titleId} className="flex items-center gap-2 text-sm font-medium">
            <Fingerprint className="h-4 w-4 text-[var(--color-accent-strong)]" aria-hidden />
            Match IOCs
          </h2>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-[var(--r-tile)] p-1 text-[var(--color-text-dim)] transition-colors hover:bg-surface-2 hover:text-[var(--color-text)]"
          >
            <X className="h-4 w-4" aria-hidden />
          </button>
        </div>

        <div className="p-4">
          <p className="mb-3 text-xs leading-relaxed text-[var(--color-text-dim)]">
            Paste IPs, domains, or file hashes (MD5/SHA-1/SHA-256), one per line. They're matched
            against this capture's hosts, contacted domains, and carved-file hashes{" "}
            <span className="text-[var(--color-text)]">entirely in your browser</span>. Nothing is uploaded.
          </p>

          <label htmlFor={`${titleId}-ta`} className="sr-only">
            IOC list
          </label>
          <textarea
            id={`${titleId}-ta`}
            value={text}
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if ((e.metaKey || e.ctrlKey) && e.key === "Enter") {
                e.preventDefault();
                submit();
              }
            }}
            rows={8}
            spellCheck={false}
            placeholder={"45.77.13.37\nevil.example.com\nhxxps://bad[.]domain[.]net/payload\n44d88612fea8a8f36de82e1278abb02f"}
            className={`${INPUT_BASE} font-mono-num w-full resize-y px-3 py-2 leading-relaxed`}
          />

          <div className="mt-2 flex items-center justify-between gap-2 text-xs">
            <span className="text-[var(--color-text-dim)]" aria-live="polite">
              {parsed.count === 0 ? (
                "No indicators yet"
              ) : (
                <>
                  <span className="font-mono-num text-[var(--color-text)]">{parsed.count}</span> indicator
                  {parsed.count === 1 ? "" : "s"}
                  <span className="text-[var(--color-text-faint)]">
                    : {parsed.ips.size} IP · {parsed.domains.size} domain · {parsed.hashes.size} hash
                  </span>
                </>
              )}
            </span>
            <button
              type="button"
              onClick={() => inputRef.current?.click()}
              className="inline-flex items-center gap-1.5 rounded-[var(--r-tile)] px-2 py-1 text-[var(--color-text-dim)] transition-colors hover:bg-surface-2 hover:text-[var(--color-text)]"
            >
              <Upload className="h-3.5 w-3.5" aria-hidden />
              Load file
            </button>
            <input
              ref={inputRef}
              type="file"
              accept=".txt,.csv,.ioc,.lst,text/plain,text/csv"
              className="hidden"
              onChange={(e) => void loadFile(e.target.files?.[0] ?? undefined)}
            />
          </div>

          <div className="mt-4 flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className={BTN_OUTLINE}
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={submit}
              disabled={parsed.count === 0}
              className={BTN_PRIMARY}
            >
              Match {parsed.count > 0 ? parsed.count : ""}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

export default IocDialog;
