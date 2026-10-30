import { Card } from "./primitives";
import { humanNumber } from "../lib/format";
import type { IndicatorKind, RareIndicator, RarityReport } from "../types";

const KIND_LABEL: Record<IndicatorKind, string> = {
  ja4: "JA4",
  ja3: "JA3",
  user_agent: "User agent",
  cert: "Certificate",
  domain: "Domain",
  destination: "Destination",
};

/** Rows shown per list; the header keeps the exact total. */
const MAX_ROWS = 12;

function Row({ r }: { r: RareIndicator }) {
  // A certificate is a SHA-256; its subject CN is the readable part. A domain's label is the
  // full name it was first seen as.
  const main = r.kind === "cert" && r.label ? r.label : r.value;
  const sub =
    r.kind === "cert"
      ? `sha256 ${r.value.slice(0, 16)}…`
      : r.label && r.label !== r.value
        ? r.label
        : undefined;
  const hosts = r.hosts.join(", ") + (r.hosts_truncated ? " +more" : "");
  return (
    <li className="flex items-baseline gap-2 py-1.5 text-xs">
      <span className="t-tag shrink-0 rounded border border-[var(--color-border)] px-1 text-[var(--color-text-dim)]">
        {KIND_LABEL[r.kind] ?? r.kind}
      </span>
      <span className="min-w-0 flex-1">
        <span className="font-mono-num block truncate text-[var(--color-text)]" title={r.value}>
          {main}
        </span>
        {sub && (
          <span className="font-mono-num block truncate text-[var(--color-text-faint)]" title={sub}>
            {sub}
          </span>
        )}
      </span>
      <span className="font-mono-num shrink-0 truncate text-[var(--color-text-dim)]" title={hosts}>
        {hosts}
      </span>
    </li>
  );
}

/**
 * Environment rarity: indicators (domains, JA4/JA3, user agents, server certificates, external
 * destinations) that no earlier capture in the saved baseline's network history saw, plus the ones
 * only a single internal host produced. "New" needs a baseline with a few captures of history;
 * the single-host list works on any capture with enough hosts. Display-only; hidden when there is
 * nothing to say.
 */
export function NewToNetworkCard({ rarity }: { rarity?: RarityReport }) {
  if (!rarity) return null;
  const fresh = rarity.new ?? [];
  const single = rarity.single_host ?? [];
  const warming = !!rarity.warming_up;
  if (fresh.length === 0 && single.length === 0 && !warming) return null;

  const history = rarity.history_captures ?? 0;
  const newTotal = rarity.new_total ?? fresh.length;
  const singleTotal = rarity.single_host_total ?? single.length;

  return (
    <Card
      label="ENVIRONMENT RARITY"
      title="New to this network"
      right={
        rarity.baseline_loaded && !warming ? (
          <span className="font-mono-num t-tag text-[var(--color-text-dim)]">
            {humanNumber(newTotal)} new · vs {humanNumber(history)} captures
          </span>
        ) : undefined
      }
    >
      {warming && (
        <p className="py-1.5 text-xs text-[var(--color-text-dim)]">
          The baseline has {humanNumber(history)} capture{history === 1 ? "" : "s"} of network
          history. Nothing is called new until it has a few more.
        </p>
      )}
      {!rarity.baseline_loaded && fresh.length === 0 && (
        <p className="py-1.5 text-xs text-[var(--color-text-dim)]">
          Load a baseline to see what is new to this network.
        </p>
      )}
      {fresh.length > 0 && (
        <ul className="flex flex-col divide-y divide-[var(--color-border)]">
          {fresh.slice(0, MAX_ROWS).map((r) => (
            <Row key={`new-${r.kind}-${r.value}`} r={r} />
          ))}
        </ul>
      )}
      {single.length > 0 && (
        <>
          <div className="t-label mt-3 mb-1 flex justify-between">
            <span>Only one host</span>
            <span className="font-mono-num">{humanNumber(singleTotal)}</span>
          </div>
          <ul className="flex flex-col divide-y divide-[var(--color-border)]">
            {single.slice(0, MAX_ROWS).map((r) => (
              <Row key={`one-${r.kind}-${r.value}`} r={r} />
            ))}
          </ul>
        </>
      )}
      {rarity.incomplete && (
        <p className="pt-2 text-xs text-[var(--color-text-faint)]">
          Very busy capture: some values were past the tracking limit and not compared.
        </p>
      )}
    </Card>
  );
}

export default NewToNetworkCard;
