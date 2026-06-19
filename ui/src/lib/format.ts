// Formatting helpers. Pure, dependency-free.

const numberFmt = new Intl.NumberFormat("en-US");

/** Group-separated integer/decimal, e.g. 119992 -> "119,992". */
export function humanNumber(n: number): string {
  if (!Number.isFinite(n)) return "—";
  return numberFmt.format(n);
}

/** Compact count, e.g. 119992 -> "120K". */
export function compactNumber(n: number): string {
  if (!Number.isFinite(n)) return "—";
  return new Intl.NumberFormat("en-US", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(n);
}

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB", "PB"];

/** Base-1024 byte formatting, e.g. 9977014 -> "9.51 MB". */
export function humanBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return "—";
  if (bytes <= 0) return "0 B";
  const i = Math.min(
    BYTE_UNITS.length - 1,
    Math.floor(Math.log(bytes) / Math.log(1024)),
  );
  const value = bytes / Math.pow(1024, i);
  const digits = i === 0 ? 0 : value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${BYTE_UNITS[i]}`;
}

/** Nanoseconds (epoch) -> JS Date. */
export function nsToDate(ns: number): Date {
  return new Date(ns / 1e6);
}

/** Nanoseconds (epoch) -> ISO-ish UTC datetime string. */
export function nsToDateTime(ns: number): string {
  return nsToDate(ns).toISOString().replace("T", " ").replace("Z", " UTC");
}

/** Nanoseconds (epoch) -> UTC HH:MM:SS. */
export function nsToTime(ns: number): string {
  return nsToDate(ns).toISOString().slice(11, 19);
}

/** Milliseconds (epoch) -> UTC HH:MM:SS.mmm. */
export function msToTime(ms: number): string {
  return new Date(ms).toISOString().slice(11, 23);
}

/** Human duration from a nanosecond span, e.g. 119931568000 -> "1m 59.9s". */
export function durationHumanNs(ns: number): string {
  return durationHumanMs(ns / 1e6);
}

/** Human duration from a millisecond span. */
export function durationHumanMs(ms: number): string {
  if (!Number.isFinite(ms)) return "—";
  if (ms < 1) return `${ms.toFixed(0)} ms`;
  const totalSec = ms / 1000;
  if (totalSec < 60) return `${totalSec.toFixed(totalSec < 10 ? 2 : 1)}s`;
  const m = Math.floor(totalSec / 60);
  const s = totalSec - m * 60;
  if (m < 60) return `${m}m ${s.toFixed(1)}s`;
  const h = Math.floor(m / 60);
  const mm = m - h * 60;
  return `${h}h ${mm}m`;
}

/** Percentage of a total, e.g. (3, 12) -> "25.0%". */
export function percent(part: number, total: number, digits = 1): string {
  if (!total) return "0%";
  return `${((part / total) * 100).toFixed(digits)}%`;
}

/** Basename of a forward/back-slash path. */
export function basename(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] || path;
}

/** Truncate a hash to head…tail. */
export function shortHash(hash: string, head = 8, tail = 6): string {
  if (hash.length <= head + tail + 1) return hash;
  return `${hash.slice(0, head)}…${hash.slice(-tail)}`;
}
