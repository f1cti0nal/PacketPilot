import { useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { X, ArrowRight, ArrowLeft, Loader2 } from "lucide-react";
import { cn } from "../lib/cn";
import { humanBytes, humanNumber } from "../lib/format";
import { hexLines } from "../lib/hexdump";
import { FOCUSABLE } from "../lib/useDialogA11y";
import type { FlowPackets, FlowRow } from "../types";

const ROW_H = 28;

export function PacketInspector({ flow, packets, loading, error, onClose }: {
  flow: FlowRow; packets: FlowPackets | null; loading: boolean; error: string | null; onClose: () => void;
}) {
  const [sel, setSel] = useState(0);
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
          <button ref={closeRef} type="button" onClick={onClose} aria-label="Close packet inspector" className="rounded-[var(--r-tile)] p-1.5 text-[var(--color-text-faint)] hover:bg-[var(--color-surface-2)] hover:text-[var(--color-text)]"><X size={16} /></button>
        </header>

        {loading ? (
          <div className="flex flex-1 items-center justify-center gap-2 text-[var(--color-text-faint)]"><Loader2 size={16} className="animate-spin" /><span>Extracting packets…</span></div>
        ) : error ? (
          <div className="flex flex-1 items-center justify-center px-6 text-center text-sm text-[var(--color-text-faint)]">{error}</div>
        ) : rows.length === 0 ? (
          <div className="flex flex-1 items-center justify-center text-sm text-[var(--color-text-faint)]">No packets matched this flow.</div>
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
                      <span className="w-24 shrink-0 text-[var(--color-text-faint)]">{tcpFlagLabel(p.tcpFlags)}</span>
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

function tcpFlagLabel(flags: number): string {
  if (!flags) return "";
  const names: [number, string][] = [[0x02, "SYN"], [0x10, "ACK"], [0x01, "FIN"], [0x04, "RST"], [0x08, "PSH"], [0x20, "URG"]];
  return names.filter(([b]) => flags & b).map(([, n]) => n).join(" ");
}
function asciiPreview(bytes: Uint8Array): string {
  return Array.from(bytes.subarray(0, 32), (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("");
}
export default PacketInspector;
