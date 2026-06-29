import { useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { X, ArrowRight, ArrowLeft, Loader2 } from "lucide-react";
import { cn } from "../lib/cn";
import { humanBytes, humanNumber } from "../lib/format";
import { hexLines } from "../lib/hexdump";
import { FOCUSABLE } from "../lib/useDialogA11y";
import { tcpFlagsLabel } from "../lib/tcpFlags";
import { buildStream, streamText } from "../lib/followStream";
import type { FlowPackets, FlowRow, PacketRow } from "../types";

const ROW_H = 28;

export function PacketInspector({ flow, packets, loading, error, onClose }: {
  flow: FlowRow; packets: FlowPackets | null; loading: boolean; error: string | null; onClose: () => void;
}) {
  const [sel, setSel] = useState(0);
  const [mode, setMode] = useState<"packets" | "stream">("packets");
  const [streamHex, setStreamHex] = useState(false);
  useEffect(() => { setSel(0); }, [packets]);
  const closeRef = useRef<HTMLButtonElement>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const sectionRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") { onClose(); return; }
      if (e.key === "Tab" && sectionRef.current) {
        const f = sectionRef.current.querySelectorAll<HTMLElement>(FOCUSABLE);
        if (f.length > 0) {
          const first = f[0];
          const last = f[f.length - 1];
          if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
          else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
        }
      }
    };
    window.addEventListener("keydown", onKey);
    return () => { window.removeEventListener("keydown", onKey); prev?.focus?.(); };
  }, [onClose]);

  const rows = packets?.packets ?? [];
  const virtualizer = useVirtualizer({ count: rows.length, getScrollElement: () => scrollRef.current, estimateSize: () => ROW_H, overscan: 12 });
  const selected = rows[sel] ?? null;

  return (
    <div role="dialog" aria-modal="true" aria-label={`Packets for ${flow.srcIp}:${flow.srcPort} to ${flow.dstIp}:${flow.dstPort}`} className="fixed inset-0 z-50 flex items-stretch justify-end">
      <button aria-hidden type="button" tabIndex={-1} onClick={onClose} className="absolute inset-0 bg-black/50 backdrop-blur-sm" />
      <section ref={sectionRef} className="glass-band relative flex h-full w-full max-w-[860px] flex-col border-l border-[var(--color-border)]">
        <header className="flex items-center gap-3 border-b border-[var(--color-border)] px-4 py-3">
          <div className="min-w-0 flex-1">
            <div className="font-mono-num truncate text-[13px] text-[var(--color-text)]">{flow.srcIp}:{flow.srcPort} → {flow.dstIp}:{flow.dstPort}</div>
            <div className="t-tag text-[var(--color-text-faint)]">
              {flow.protoLabel}
              {packets?.truncated ? ` · first ${humanNumber(rows.length)} of ${humanNumber(packets.total)} packets` : packets ? ` · ${humanNumber(packets.total)} packets` : ""}
            </div>
          </div>
          {rows.length > 0 && (
            <div className="flex shrink-0 rounded-[var(--r-tile)] border border-[var(--color-border)] p-0.5 text-xs" role="group" aria-label="Inspector view">
              {(["packets", "stream"] as const).map((m) => (
                <button key={m} type="button" onClick={() => setMode(m)} aria-pressed={mode === m}
                  className={cn("rounded-[var(--r-micro)] px-2 py-0.5 capitalize",
                    mode === m ? "bg-[var(--color-surface-2)] text-[var(--color-text)]" : "text-[var(--color-text-faint)] hover:text-[var(--color-text)]")}>
                  {m}
                </button>
              ))}
            </div>
          )}
          <button ref={closeRef} type="button" onClick={onClose} aria-label="Close packet inspector" className="rounded-[var(--r-tile)] p-1.5 text-[var(--color-text-faint)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"><X size={16} /></button>
        </header>

        {loading ? (
          <div className="flex flex-1 items-center justify-center gap-2 text-[var(--color-text-faint)]"><Loader2 size={16} className="animate-spin" /><span>Extracting packets…</span></div>
        ) : error ? (
          <div className="flex flex-1 items-center justify-center px-6 text-center text-sm text-[var(--color-text-faint)]">{error}</div>
        ) : rows.length === 0 ? (
          <div className="flex flex-1 items-center justify-center text-sm text-[var(--color-text-faint)]">No packets matched this flow.</div>
        ) : mode === "stream" ? (
          <StreamView rows={rows} listTruncated={packets?.truncated ?? false} hex={streamHex} onToggleHex={() => setStreamHex((h) => !h)} />
        ) : (
          <div className="flex min-h-0 flex-1 flex-col">
            <div ref={scrollRef} className="min-h-0 flex-1 overflow-y-auto">
              <div className="relative" style={{ height: virtualizer.getTotalSize() }}>
                {virtualizer.getVirtualItems().map((vi) => {
                  const p = rows[vi.index];
                  const active = vi.index === sel;
                  return (
                    <button key={vi.key} type="button" onClick={() => setSel(vi.index)} aria-current={active ? "true" : undefined}
                      className={cn("absolute inset-x-0 flex items-center gap-3 px-4 text-left font-mono-num text-xs", active ? "bg-[var(--color-surface-2)]" : "hover:bg-[var(--color-surface-1)]")}
                      style={{ height: ROW_H, transform: `translateY(${vi.start}px)` }}>
                      <span className="w-10 shrink-0 text-[var(--color-text-faint)]">{p.index}</span>
                      <span className="w-16 shrink-0 tabular-nums text-[var(--color-text-faint)]">{p.relMs.toFixed(1)}ms</span>
                      <span className="w-5 shrink-0" aria-label={p.direction === "c2s" ? "client to server" : "server to client"}>
                        {p.direction === "c2s" ? <ArrowRight size={13} className="text-[var(--color-accent)]" /> : <ArrowLeft size={13} className="text-[var(--color-text-faint)]" />}
                      </span>
                      <span className="w-16 shrink-0 tabular-nums">{humanBytes(p.wireLen)}</span>
                      <span className="w-24 shrink-0 text-[var(--color-text-faint)]">{tcpFlagsLabel(p.tcpFlags)}</span>
                      <span className="w-14 shrink-0 tabular-nums text-[var(--color-text-faint)]">{p.payloadLen}B</span>
                      <span className="min-w-0 flex-1 truncate text-[var(--color-text-faint)]">{asciiPreview(p.payload)}</span>
                    </button>
                  );
                })}
              </div>
            </div>
            <div className="max-h-[40%] min-h-[120px] overflow-y-auto border-t border-[var(--color-border)] bg-[var(--color-surface-1)] p-3">
              {selected && selected.payload.length > 0 ? (
                <table className="font-mono-num text-xs leading-5"><tbody>
                  {hexLines(selected.payload).map((ln) => (
                    <tr key={ln.offset}>
                      <td className="pr-4 text-[var(--color-text-faint)]">{ln.offset}</td>
                      <td className="whitespace-pre pr-4 text-[var(--color-text)]">{ln.hex}</td>
                      <td className="whitespace-pre text-[var(--color-text-faint)]">{ln.ascii}</td>
                    </tr>
                  ))}
                </tbody></table>
              ) : (
                <div className="text-xs text-[var(--color-text-faint)]">No payload in this packet.</div>
              )}
              {selected?.payloadTruncated && <div className="t-tag mt-2 text-[var(--color-text-faint)]">payload truncated to {selected.payload.length} bytes shown</div>}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
function StreamView({ rows, listTruncated, hex, onToggleHex }: {
  rows: PacketRow[]; listTruncated: boolean; hex: boolean; onToggleHex: () => void;
}) {
  const stream = useMemo(() => buildStream(rows, listTruncated), [rows, listTruncated]);
  const copy = () => { void navigator.clipboard?.writeText(stream.segments.map((s) => streamText(s.bytes)).join("")); };
  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center gap-3 border-b border-[var(--color-border)] px-4 py-2 text-xs">
        <span className="inline-flex items-center gap-1 text-[var(--color-accent)]"><ArrowRight size={12} aria-hidden /> {humanBytes(stream.bytesC2s)}</span>
        <span className="inline-flex items-center gap-1 text-[var(--color-text-faint)]"><ArrowLeft size={12} aria-hidden /> {humanBytes(stream.bytesS2c)}</span>
        <div className="ml-auto flex items-center gap-1.5">
          <button type="button" onClick={onToggleHex} aria-pressed={hex} className="rounded-[var(--r-micro)] border border-[var(--color-border)] px-2 py-0.5 text-[var(--color-text-dim)] hover:text-[var(--color-text)]">{hex ? "Text" : "Hex"}</button>
          <button type="button" onClick={copy} className="rounded-[var(--r-micro)] border border-[var(--color-border)] px-2 py-0.5 text-[var(--color-text-dim)] hover:text-[var(--color-text)]">Copy</button>
        </div>
      </div>
      {(stream.truncated || stream.payloadCapped) && (
        <div className="border-b border-[var(--color-border)] bg-[var(--color-surface-1)] px-4 py-1.5 t-tag text-[var(--color-text-faint)]">
          {stream.truncated && <span>Showing the first {humanNumber(rows.length)} packets — stream is partial. </span>}
          {stream.payloadCapped && <span>Payloads are capped per packet; segments show a prefix.</span>}
        </div>
      )}
      <div className="min-h-0 flex-1 overflow-y-auto p-3">
        {stream.segments.length === 0 ? (
          <div className="text-sm text-[var(--color-text-faint)]">No payload bytes in this flow — only control packets (SYN/ACK/FIN).</div>
        ) : (
          stream.segments.map((seg, i) => (
            <div key={i} className="mb-2 pl-2" style={{ borderLeft: `2px solid ${seg.direction === "c2s" ? "var(--color-accent)" : "var(--color-border-strong)"}` }}>
              <div className="t-tag mb-0.5 text-[var(--color-text-faint)]">
                {seg.direction === "c2s" ? "client → server" : "server → client"} · {humanBytes(seg.bytes.length)}{seg.truncatedPayload ? " (prefix)" : ""}
              </div>
              {hex ? (
                <table className="font-mono-num text-xs leading-5"><tbody>
                  {hexLines(seg.bytes).map((ln) => (
                    <tr key={ln.offset}>
                      <td className="pr-4 text-[var(--color-text-faint)]">{ln.offset}</td>
                      <td className="whitespace-pre pr-4 text-[var(--color-text)]">{ln.hex}</td>
                      <td className="whitespace-pre text-[var(--color-text-faint)]">{ln.ascii}</td>
                    </tr>
                  ))}
                </tbody></table>
              ) : (
                <pre className="whitespace-pre-wrap break-all font-mono-num text-xs leading-5" style={{ color: seg.direction === "c2s" ? "var(--color-text)" : "var(--color-text-dim)" }}>{streamText(seg.bytes)}</pre>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function asciiPreview(bytes: Uint8Array): string {
  return Array.from(bytes.subarray(0, 32), (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
}
export default PacketInspector;
