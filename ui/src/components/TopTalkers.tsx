import { useMemo } from "react";
import {
  createColumnHelper,
  flexRender,
  getCoreRowModel,
  useReactTable,
  type CellContext,
} from "@tanstack/react-table";
import { Network } from "lucide-react";
import type { TopTalker } from "../types";
import { humanBytes, humanNumber } from "../lib/format";

export interface TopTalkersProps {
  talkers: TopTalker[];
  limit?: number; // default 15
  onSelect?: (ip: string) => void;
}

const DEFAULT_LIMIT = 15;

const columnHelper = createColumnHelper<TopTalker>();

/** Subtle in-row bar showing a row's bytes relative to the busiest talker. */
function BytesCell({
  cell,
  maxBytes,
}: {
  cell: CellContext<TopTalker, number>;
  maxBytes: number;
}) {
  const bytes = cell.getValue();
  const pct = maxBytes > 0 ? Math.max(2, (bytes / maxBytes) * 100) : 0;
  return (
    <div className="relative flex items-center justify-end">
      <div
        aria-hidden
        className="pointer-events-none absolute inset-y-0 right-0 rounded-sm bg-[color-mix(in_srgb,var(--color-accent)_14%,transparent)]"
        style={{ width: `${pct}%` }}
      />
      <span className="font-mono-num relative z-10 text-[var(--color-text)]">
        {humanBytes(bytes)}
      </span>
    </div>
  );
}

export function TopTalkers({
  talkers,
  limit = DEFAULT_LIMIT,
  onSelect,
}: TopTalkersProps) {
  const rows = useMemo(
    () => talkers.slice(0, limit),
    [talkers, limit],
  );

  const maxBytes = useMemo(
    () => rows.reduce((m, t) => (t.bytes > m ? t.bytes : m), 0),
    [rows],
  );

  const columns = useMemo(
    () => [
      columnHelper.accessor("ip", {
        header: "Host",
        cell: (c) => (
          <span className="font-mono-num text-[var(--color-text)]">
            {c.getValue()}
          </span>
        ),
      }),
      columnHelper.accessor("pkts", {
        header: "Packets",
        cell: (c) => (
          <span className="font-mono-num text-[var(--color-text-dim)]">
            {humanNumber(c.getValue())}
          </span>
        ),
      }),
      columnHelper.accessor("bytes", {
        header: "Bytes",
        cell: (c) => <BytesCell cell={c} maxBytes={maxBytes} />,
      }),
      columnHelper.accessor("flows", {
        header: "Flows",
        cell: (c) => (
          <span className="font-mono-num text-[var(--color-text-dim)]">
            {humanNumber(c.getValue())}
          </span>
        ),
      }),
    ],
    [maxBytes],
  );

  const table = useReactTable({
    data: rows,
    columns,
    getCoreRowModel: getCoreRowModel(),
  });

  if (rows.length === 0) {
    return (
      <div
        data-component="TopTalkers"
        className="flex items-center gap-2 px-3 py-6 text-sm text-[var(--color-text-faint)]"
      >
        <Network size={16} aria-hidden />
        <span>No talkers observed.</span>
      </div>
    );
  }

  return (
    <div data-component="TopTalkers" className="w-full overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <thead>
          {table.getHeaderGroups().map((hg) => (
            <tr key={hg.id} className="border-b border-[var(--color-border)]">
              {hg.headers.map((header, i) => (
                <th
                  key={header.id}
                  scope="col"
                  className={`px-3 py-2 text-xs font-medium uppercase tracking-wide text-[var(--color-text-faint)] ${
                    i === 0 ? "text-left" : "text-right"
                  }`}
                >
                  {flexRender(
                    header.column.columnDef.header,
                    header.getContext(),
                  )}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {table.getRowModel().rows.map((row) => {
            const ip = row.original.ip;
            const interactive = typeof onSelect === "function";
            return (
              <tr
                key={row.id}
                onClick={interactive ? () => onSelect?.(ip) : undefined}
                tabIndex={interactive ? 0 : undefined}
                role={interactive ? "button" : undefined}
                onKeyDown={
                  interactive
                    ? (e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          onSelect?.(ip);
                        }
                      }
                    : undefined
                }
                className={`border-b border-[var(--color-grid)] transition-colors last:border-b-0 ${
                  interactive
                    ? "cursor-pointer hover:bg-[var(--color-surface-2)] focus:bg-[var(--color-surface-2)] focus:outline-none"
                    : ""
                }`}
              >
                {row.getVisibleCells().map((cell, i) => (
                  <td
                    key={cell.id}
                    className={`px-3 py-1.5 ${
                      i === 0 ? "text-left" : "text-right"
                    }`}
                  >
                    {flexRender(cell.column.columnDef.cell, cell.getContext())}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default TopTalkers;
