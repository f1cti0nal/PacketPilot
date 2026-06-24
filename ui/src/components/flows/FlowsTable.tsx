import { useCallback, useMemo, useRef } from "react";
import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type SortDirection,
  type SortingState,
  type OnChangeFn,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDown, ArrowUp, ChevronsUpDown } from "lucide-react";
import clsx from "clsx";
import type { FlowRow, Severity } from "../../types";
import { SEVERITY_META, severityForCategory } from "../../lib/severity";
import { severityColor } from "../../lib/palette";
import { humanBytes, humanNumber, msToTime } from "../../lib/format";

// Rank used to make the Severity column sortable (critical highest).
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  none: 0,
};

export interface FlowsTableProps {
  rows: FlowRow[];
  sorting: SortingState;
  onSortingChange: OnChangeFn<SortingState>;
  onRowClick: (row: FlowRow) => void;
  selectedFlowId?: number | null;
}

// Fixed row height keeps the virtualizer math exact and the scroll buttery.
const ROW_HEIGHT = 36;
const OVERSCAN = 12;

// Human label for the snake_case parquet category token.
function categoryLabel(category: string): string {
  return category
    .split("_")
    .map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w))
    .join(" ");
}

function CategoryChip({ category }: { category: string }) {
  const sev: Severity = severityForCategory(category);
  const color = `var(${SEVERITY_META[sev].cssVar})`;
  return (
    <span
      className="inline-flex max-w-full items-center gap-1.5 truncate rounded-full border px-2 py-0.5 text-xs font-medium"
      style={{
        color,
        borderColor: color,
        backgroundColor: `color-mix(in srgb, ${color} 14%, transparent)`,
      }}
      title={categoryLabel(category)}
    >
      <span
        aria-hidden
        className="h-1.5 w-1.5 shrink-0 rounded-full"
        style={{ backgroundColor: color }}
      />
      <span className="truncate">{categoryLabel(category)}</span>
    </span>
  );
}

function SeverityCell({ flow }: { flow: FlowRow }) {
  const color = severityColor(flow.severity);
  const label = SEVERITY_META[flow.severity].label;
  return (
    <span className="flex min-w-0 items-center gap-1.5">
      <span
        className="inline-flex max-w-full items-center gap-1.5 truncate rounded-full border px-2 py-0.5 text-xs font-medium"
        style={{
          color,
          borderColor: color,
          backgroundColor: `color-mix(in srgb, ${color} 14%, transparent)`,
        }}
      >
        <span
          aria-hidden
          className="h-1.5 w-1.5 shrink-0 rounded-full"
          style={{ backgroundColor: color }}
        />
        <span className="truncate">{label}</span>
      </span>
      {flow.ioc && (
        <span
          className="shrink-0 rounded px-1 py-0.5 text-[0.6rem] font-semibold"
          style={{
            color: "var(--color-sev-critical)",
            backgroundColor:
              "color-mix(in srgb, var(--color-sev-critical) 16%, transparent)",
          }}
          title={`IOC — threat score ${flow.threatScore}/100`}
        >
          IOC
        </span>
      )}
    </span>
  );
}

function SortIcon({ dir }: { dir: SortDirection | false }) {
  if (dir === "asc") return <ArrowUp className="h-3.5 w-3.5" aria-hidden />;
  if (dir === "desc") return <ArrowDown className="h-3.5 w-3.5" aria-hidden />;
  return (
    <ChevronsUpDown
      className="h-3.5 w-3.5 opacity-0 transition-opacity group-hover:opacity-60"
      aria-hidden
    />
  );
}

export function FlowsTable({
  rows,
  sorting,
  onSortingChange,
  onRowClick,
  selectedFlowId,
}: FlowsTableProps) {
  const columns = useMemo<ColumnDef<FlowRow>[]>(
    () => [
      {
        id: "time",
        header: "Time",
        accessorKey: "startMs",
        size: 130,
        cell: ({ row }) => (
          <span className="font-mono-num text-[var(--color-text-dim)]">
            {msToTime(row.original.startMs)}
          </span>
        ),
      },
      {
        id: "source",
        header: "Source",
        // Sort by the literal endpoint string so it groups sensibly.
        accessorFn: (r) => `${r.srcIp}:${r.srcPort}`,
        size: 190,
        cell: ({ row }) => {
          const f = row.original;
          return (
            <span className="font-mono-num truncate">
              <span className="text-[var(--color-text)]">{f.srcIp}</span>
              <span className="text-[var(--color-text-faint)]">:{f.srcPort}</span>
            </span>
          );
        },
      },
      {
        id: "arrow",
        header: "",
        enableSorting: false,
        size: 28,
        cell: () => (
          <span className="text-[var(--color-text-faint)]" aria-hidden>
            →
          </span>
        ),
      },
      {
        id: "dest",
        header: "Destination",
        accessorFn: (r) => `${r.dstIp}:${r.dstPort}`,
        size: 190,
        cell: ({ row }) => {
          const f = row.original;
          return (
            <span className="font-mono-num truncate">
              <span className="text-[var(--color-text)]">{f.dstIp}</span>
              <span className="text-[var(--color-text-faint)]">:{f.dstPort}</span>
            </span>
          );
        },
      },
      {
        id: "proto",
        header: "Proto / App / SNI",
        accessorKey: "protoLabel",
        size: 220,
        cell: ({ row }) => {
          const f = row.original;
          const payload = f.appProtoSrc === "payload";
          return (
            <span className="flex min-w-0 items-baseline gap-1.5 truncate">
              <span className="font-medium text-[var(--color-text)]">
                {f.protoLabel}
              </span>
              {f.appProto && (
                <span
                  className="font-mono-num inline-flex shrink-0 items-center gap-1 text-xs text-[var(--color-text-dim)]"
                  title={
                    payload
                      ? "App protocol detected by payload inspection (DPI)"
                      : "App protocol inferred from the well-known port"
                  }
                >
                  {f.appProto}
                  {payload && (
                    <span
                      aria-hidden
                      className="h-1.5 w-1.5 rounded-full bg-[var(--color-accent)]"
                    />
                  )}
                </span>
              )}
              {f.sni && (
                <span
                  className="font-mono-num truncate text-xs text-[var(--color-text-faint)]"
                  title={`SNI: ${f.sni}`}
                >
                  {f.sni}
                </span>
              )}
              {(f.ja3 || f.ja4) && (
                <span
                  className="font-mono-num truncate text-xs text-[var(--color-text-faint)]"
                  title={[f.ja3 && `JA3: ${f.ja3}`, f.ja4 && `JA4: ${f.ja4}`].filter(Boolean).join("\n")}
                >
                  {f.ja4 ? `JA4 ${f.ja4.slice(0, 12)}…` : `JA3 ${f.ja3!.slice(0, 12)}…`}
                </span>
              )}
              {f.tlsVersion && (
                <span
                  className="font-mono-num shrink-0 rounded border border-[var(--color-border)] px-1 text-[0.65rem] text-[var(--color-text-faint)]"
                  title={f.tlsCipher ? `${f.tlsVersion} · ${f.tlsCipher}` : f.tlsVersion}
                >
                  {f.tlsVersion}
                </span>
              )}
            </span>
          );
        },
      },
      {
        id: "category",
        header: "Category",
        accessorKey: "category",
        size: 150,
        cell: ({ row }) => <CategoryChip category={row.original.category} />,
      },
      {
        id: "severity",
        header: "Severity",
        // Rank so critical sorts above high above … above info.
        accessorFn: (r) => SEVERITY_RANK[r.severity],
        size: 130,
        cell: ({ row }) => <SeverityCell flow={row.original} />,
      },
      {
        id: "bytes",
        header: "Bytes",
        accessorKey: "bytesTotal",
        size: 100,
        meta: { align: "right" as const },
        cell: ({ row }) => (
          <span className="font-mono-num block text-right text-[var(--color-text-dim)]">
            {humanBytes(row.original.bytesTotal)}
          </span>
        ),
      },
      {
        id: "pkts",
        header: "Pkts",
        accessorKey: "pkts",
        size: 80,
        meta: { align: "right" as const },
        cell: ({ row }) => (
          <span className="font-mono-num block text-right text-[var(--color-text-dim)]">
            {humanNumber(row.original.pkts)}
          </span>
        ),
      },
    ],
    [],
  );

  const table = useReactTable({
    data: rows,
    columns,
    state: { sorting },
    onSortingChange,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getRowId: (r) => String(r.flowIdBig),
    enableSortingRemoval: true,
    enableMultiSort: false,
  });

  const tableRows = table.getRowModel().rows;
  const totalWidth = table.getTotalSize();

  const scrollRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: tableRows.length,
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

  const handleRowClick = useCallback(
    (row: FlowRow) => onRowClick(row),
    [onRowClick],
  );

  const headerGroups = table.getHeaderGroups();

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden rounded-lg border border-border bg-surface">
      <div
        ref={scrollRef}
        className="min-h-0 flex-1 overflow-auto"
        role="grid"
        aria-rowcount={tableRows.length}
      >
        <div style={{ width: totalWidth, minWidth: "100%" }}>
          {/* Sticky header */}
          <div className="sticky top-0 z-10 border-b border-border bg-surface-2">
            {headerGroups.map((hg) => (
              <div key={hg.id} className="flex" role="row">
                {hg.headers.map((header) => {
                  const canSort = header.column.getCanSort();
                  const align =
                    (
                      header.column.columnDef.meta as
                        | { align?: "right" }
                        | undefined
                    )?.align === "right";
                  return (
                    <div
                      key={header.id}
                      role="columnheader"
                      aria-sort={
                        header.column.getIsSorted() === "asc"
                          ? "ascending"
                          : header.column.getIsSorted() === "desc"
                            ? "descending"
                            : canSort
                              ? "none"
                              : undefined
                      }
                      style={{ width: header.getSize() }}
                      className={clsx(
                        "group flex shrink-0 items-center gap-1 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-[var(--color-text-dim)] select-none",
                        align && "justify-end text-right",
                        canSort &&
                          "cursor-pointer transition-colors hover:text-[var(--color-text)]",
                      )}
                      onClick={
                        canSort
                          ? header.column.getToggleSortingHandler()
                          : undefined
                      }
                    >
                      <span className="truncate">
                        {flexRender(
                          header.column.columnDef.header,
                          header.getContext(),
                        )}
                      </span>
                      {canSort && (
                        <SortIcon dir={header.column.getIsSorted()} />
                      )}
                    </div>
                  );
                })}
              </div>
            ))}
          </div>

          {/* Virtualized body — only the visible window is in the DOM */}
          <div role="rowgroup">
            {paddingTop > 0 && <div style={{ height: paddingTop }} />}
            {virtualItems.map((vi) => {
              const row = tableRows[vi.index];
              const flow = row.original;
              const selected = selectedFlowId === flow.flowId;
              return (
                <div
                  key={row.id}
                  role="row"
                  aria-selected={selected}
                  aria-rowindex={vi.index + 1}
                  onClick={() => handleRowClick(flow)}
                  style={{ height: ROW_HEIGHT }}
                  className={clsx(
                    "flex cursor-pointer items-center border-b border-border/60 text-sm transition-colors",
                    selected
                      ? "bg-[color-mix(in_srgb,var(--color-accent)_16%,transparent)] ring-1 ring-inset ring-[var(--color-accent)]"
                      : vi.index % 2 === 1
                        ? "bg-surface hover:bg-surface-2"
                        : "bg-transparent hover:bg-surface-2",
                  )}
                >
                  {row.getVisibleCells().map((cell) => (
                    <div
                      key={cell.id}
                      role="gridcell"
                      style={{ width: cell.column.getSize() }}
                      className="flex min-w-0 shrink-0 items-center px-3"
                    >
                      {flexRender(
                        cell.column.columnDef.cell,
                        cell.getContext(),
                      )}
                    </div>
                  ))}
                </div>
              );
            })}
            {paddingBottom > 0 && <div style={{ height: paddingBottom }} />}
          </div>
        </div>
      </div>
    </div>
  );
}

export default FlowsTable;
