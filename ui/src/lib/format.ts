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

const pad2 = (n: number): string => String(n).padStart(2, "0");
const pad3 = (n: number): string => String(n).padStart(3, "0");
const timeLocal = (d: Date): string =>
  `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;

/** Browser's short timezone label (e.g. "PST", "GMT+5:30"), computed once. Never throws. */
export const localTzLabel: string = (() => {
  try {
    const parts = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" }).formatToParts(
      new Date(),
    );
    return parts.find((p) => p.type === "timeZoneName")?.value ?? "local";
  } catch {
    return "local";
  }
})();

/** LOCAL calendar date "YYYY-MM-DD" from a Date (local getters, NOT toISOString which is UTC). */
export function dateLocal(d: Date): string {
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
}

/** Nanoseconds (epoch) -> LOCAL "YYYY-MM-DD HH:MM:SS <TZ>" so on-screen times match the analyst's
 *  local-time Wireshark view. Exports (CSV, the WASM HTML report) stay UTC for portability. */
export function nsToDateTime(ns: number): string {
  const d = nsToDate(ns);
  return `${dateLocal(d)} ${timeLocal(d)} ${localTzLabel}`;
}

/** Nanoseconds (epoch) -> LOCAL HH:MM:SS. Bare (no tz) since axis ticks repeat; the tz is surfaced
 *  once at the axis/label level. */
export function nsToTime(ns: number): string {
  return timeLocal(nsToDate(ns));
}

/** Milliseconds (epoch) -> LOCAL HH:MM:SS.mmm. */
export function msToTime(ms: number): string {
  const d = new Date(ms);
  return `${timeLocal(d)}.${pad3(d.getMilliseconds())}`;
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

/** Compact relative-time from an epoch-ms timestamp, e.g. "just now", "3m ago", "2h ago", "Apr 5". */
export function relativeTime(ts: number): string {
  const sec = Math.round((Date.now() - ts) / 1000);
  if (sec < 45) return "just now";
  const min = Math.round(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.round(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.round(hr / 24);
  if (day < 7) return `${day}d ago`;
  return new Date(ts).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}
