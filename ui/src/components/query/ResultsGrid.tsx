import { useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { clsx } from "clsx";
import type { QueryResult } from "../../lib/query/engine";
import { formatCell, isTimestampColumn } from "../../lib/query/results";

/** Mirrors FlowsTable's virtualization metrics (fixed rows, small overscan). */
const ROW_HEIGHT = 32;
const OVERSCAN = 12;

/** Right-align numbers/timestamps; everything else reads left-to-right. */
function isNumericType(type: string): boolean {
  return /^(u?int|float|decimal|timestamp)/i.test(type);
}

/**
 * Generic virtualized grid for arbitrary query results — dynamic columns from
 * the result schema, unlike FlowsTable's fixed FlowRow columns. Read-only (no
 * sorting/selection): ORDER BY belongs in the query itself.
 */
export function ResultsGrid({ result }: { result: QueryResult }) {
  const { columns, rows } = result;
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: OVERSCAN,
  });

  const virtualItems = virtualizer.getVirtualItems();
  const totalHeight = virtualizer.getTotalSize();
  const paddingTop = virtualItems.length ? virtualItems[0].start : 0;
  const paddingBottom = virtualItems.length
    ? totalHeight - virtualItems[virtualItems.length - 1].end
    : 0;

  const numeric = columns.map((c) => isNumericType(c.type));
  const mono = columns.map((c, i) => numeric[i] || isTimestampColumn(c));
  // Each column gets an equal share but never shrinks below a readable width;
  // wide results scroll horizontally inside this container.
  const colStyle = { flex: "1 0 10rem" } as const;

  return (
    <div
      ref={scrollRef}
      data-component="ResultsGrid"
      className="h-full min-h-0 overflow-auto"
      role="grid"
      tabIndex={0}
      aria-rowcount={rows.length}
    >
      <div className="min-w-max" style={{ minWidth: "100%" }}>
        {/* Sticky elevated header — mirrors FlowsTable / .pp-table thead th */}
        <div
          className="sticky top-0 z-10 border-b border-[var(--color-border)] bg-[var(--color-surface-2)]"
          style={{ boxShadow: "0 1px 0 var(--color-border)" }}
        >
          <div className="flex" role="row">
            {columns.map((col, i) => (
              <div
                key={`${col.name}-${i}`}
                role="columnheader"
                title={col.type}
                style={colStyle}
                className={clsx(
                  "flex min-w-0 items-center px-[13px] py-[9px] font-normal uppercase tracking-[.04em] text-[var(--color-text-faint)] select-none",
                  "text-[length:var(--fs-label)]",
                  numeric[i] && "justify-end text-right",
                )}
              >
                <span className="truncate">{col.name}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Virtualized body — only the visible window is in the DOM */}
        <div role="rowgroup">
          {paddingTop > 0 && <div style={{ height: paddingTop }} />}
          {virtualItems.map((vi) => {
            const row = rows[vi.index];
            return (
              <div
                key={vi.index}
                role="row"
                aria-rowindex={vi.index + 1}
                style={{ height: ROW_HEIGHT }}
                className="flex items-center border-t border-[var(--color-border)] text-[length:var(--fs-body)] transition-colors hover:bg-[var(--color-surface-2)]"
              >
                {row.map((value, i) => {
                  const text = formatCell(value, columns[i]);
                  const isNull = value == null;
                  return (
                    <div
                      key={i}
                      role="gridcell"
                      style={colStyle}
                      className={clsx(
                        "flex min-w-0 items-center px-[13px]",
                        numeric[i] && "justify-end",
                        mono[i] && "font-mono-num",
                        isNull ? "text-[var(--color-text-faint)]" : "text-[var(--color-text)]",
                      )}
                    >
                      <span className="truncate" title={isNull ? undefined : text}>
                        {isNull ? "∅" : text}
                      </span>
                    </div>
                  );
                })}
              </div>
            );
          })}
          {paddingBottom > 0 && <div style={{ height: paddingBottom }} />}
        </div>
      </div>
    </div>
  );
}

export default ResultsGrid;
