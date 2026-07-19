/**
 * Natural language → SQL for the Query console (NLQ plan Phase 3).
 *
 * The model translates an analyst's question into ONE read-only DuckDB SELECT
 * over the browser-local `flow` table. Privacy contract: only the question
 * text (and, on a repair round, the failing SQL + DuckDB error text) is sent —
 * never flows, packets, the summary, or the capture. The generated SQL is
 * always shown in the editor, is editable, and still passes the same
 * `guardSql` + hardened-session gauntlet as hand-typed SQL when run.
 *
 * The system prompt is assembled from the Phase 0 schema module
 * (lib/query/schema.ts), so column names, types, and semantics can never
 * drift from the engine contract without failing the shared drift guards.
 */

import { FLOW_COLUMNS } from "../../types";
import {
  FLOW_CATEGORY_TOKENS,
  FLOW_COLUMN_TYPES,
  FLOW_SEVERITY_TOKENS,
} from "../query/schema";
import { runViaProxy } from "./proxyClient";

/** DDL-with-semantics block: one commented column per line, canonical order. */
function schemaBlock(): string {
  const cols = FLOW_COLUMNS.map((name) => {
    const spec = FLOW_COLUMN_TYPES[name];
    return `  ${name} ${spec.type}${spec.nullable ? "" : " NOT NULL"}, -- ${spec.comment}`;
  });
  return ["CREATE TABLE flow (", ...cols, ");"].join("\n");
}

/** Compact few-shots teaching the output contract + flow-table idioms. */
const FEW_SHOTS = [
  {
    q: "who are the top talkers?",
    a: `-- intent: top endpoints by total bytes in either direction
WITH ep AS (
  SELECT src_ip AS ip, bytes_c2s + bytes_s2c AS bytes FROM flow
  UNION ALL
  SELECT dst_ip AS ip, bytes_c2s + bytes_s2c AS bytes FROM flow
)
SELECT ip, SUM(bytes) AS total_bytes, COUNT(*) AS flows
FROM ep GROUP BY ip ORDER BY total_bytes DESC LIMIT 25`,
  },
  {
    q: "any beaconing to unusual ports?",
    a: `-- intent: repetitive similar-sized flows to non-standard responder ports
SELECT src_ip, dst_ip, dst_port, COUNT(*) AS flow_count,
       AVG(bytes_c2s + bytes_s2c) AS avg_bytes,
       STDDEV_POP(bytes_c2s + bytes_s2c) AS std_bytes
FROM flow
WHERE dst_port NOT IN (80, 443, 53)
GROUP BY src_ip, dst_ip, dst_port
HAVING COUNT(*) >= 5
ORDER BY flow_count DESC, std_bytes ASC
LIMIT 50`,
  },
  {
    q: "show the biggest uploads",
    a: `-- intent: individual flows ranked by initiator-to-responder bytes
SELECT flow_id, src_ip, dst_ip, dst_port, app_proto, sni, bytes_c2s
FROM flow
ORDER BY bytes_c2s DESC
LIMIT 50`,
  },
  {
    q: "which TLS hosts did 10.0.0.5 contact?",
    a: `-- intent: TLS server names contacted by one initiator, with volume
SELECT sni, COUNT(*) AS flows, SUM(bytes_c2s + bytes_s2c) AS bytes
FROM flow
WHERE src_ip = '10.0.0.5' AND sni IS NOT NULL
GROUP BY sni ORDER BY bytes DESC LIMIT 100`,
  },
  {
    q: "what did the malware download?",
    a: "-- error: payload contents are not in the flow table — only per-flow metadata is queryable",
  },
];

/**
 * The NL→SQL system prompt. Static text only (schema + rules + few-shots) —
 * no capture data. nlq.test.ts enforces a byte budget well under the proxy's
 * 128 KiB content cap.
 */
export function buildNlqSystemPrompt(): string {
  return [
    "You translate a network analyst's question about ONE packet capture into a single DuckDB SQL query.",
    "The only queryable data is this table of per-flow metadata (no packets, no payloads):",
    "",
    schemaBlock(),
    "",
    "Semantics:",
    "- src_* is the connection INITIATOR (SYN sender / first packet); dst_* is the responder.",
    "- Total bytes of a flow = bytes_c2s + bytes_s2c. Uploads are bytes_c2s, downloads bytes_s2c.",
    "- start_ts/end_ts are UTC TIMESTAMPs (millisecond precision); duration = end_ts - start_ts.",
    `- category is one of: ${FLOW_CATEGORY_TOKENS.join(", ")}.`,
    `- severity is one of: ${FLOW_SEVERITY_TOKENS.join(", ")}.`,
    "- proto is the IANA number: 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6, 132=SCTP.",
    "",
    "Rules:",
    "- Reply with a line `-- intent: <one short sentence>` followed by EXACTLY ONE SELECT (or WITH … SELECT) statement. No other prose, no code fences.",
    "- Read-only DuckDB SQL only: never CREATE/INSERT/UPDATE/DELETE/DROP/ATTACH/COPY/PRAGMA/SET.",
    "- Include a LIMIT unless the query aggregates to a small result.",
    "- When listing individual flows, include flow_id so the analyst can pivot to the Flows view.",
    "- Use only columns from the schema above. String comparisons are case-sensitive; tokens are lowercase.",
    "- If the question cannot be answered from this table, reply with exactly one line: `-- error: <short reason>`.",
    "",
    "Examples:",
    ...FEW_SHOTS.flatMap(({ q, a }) => [`Q: ${q}`, a, ""]),
  ].join("\n");
}

export type ParsedNlq =
  | { kind: "sql"; sql: string; intent: string | null }
  | { kind: "error"; message: string };

/**
 * Parse a model reply: tolerate a ``` fence despite the contract, extract the
 * `-- intent:` caption (kept in the SQL as self-documentation), and map the
 * `-- error:` marker to a user-facing error.
 */
export function parseNlqResponse(raw: string): ParsedNlq {
  let text = raw.trim();
  const fence = /```(?:sql)?\s*\n([\s\S]*?)\n?\s*```/.exec(text);
  if (fence) text = fence[1].trim();
  if (text === "") return { kind: "error", message: "The model returned an empty reply." };

  const firstLine = text.split("\n", 1)[0];
  const err = /^--\s*error:\s*(.+)$/i.exec(firstLine);
  if (err) return { kind: "error", message: err[1].trim() };

  const intent = /^--\s*intent:\s*(.+)$/im.exec(text);
  return { kind: "sql", sql: text, intent: intent ? intent[1].trim() : null };
}

/** Ask the model for SQL answering `question`. Streams raw text via onToken. */
export async function generateSql(
  question: string,
  onToken: (t: string) => void,
): Promise<ParsedNlq> {
  const raw = await runViaProxy(
    [
      { role: "system", content: buildNlqSystemPrompt() },
      { role: "user", content: question },
    ],
    onToken,
  );
  return parseNlqResponse(raw);
}

/**
 * One automatic repair round: replay the exchange plus the DuckDB error and
 * ask for a corrected query. The caller gives up after this (the SQL stays
 * editable in the console).
 */
export async function repairSql(
  question: string,
  badSql: string,
  dbError: string,
  onToken: (t: string) => void,
): Promise<ParsedNlq> {
  const raw = await runViaProxy(
    [
      { role: "system", content: buildNlqSystemPrompt() },
      { role: "user", content: question },
      { role: "assistant", content: badSql },
      {
        role: "user",
        content: `That query failed with this DuckDB error:\n${dbError}\nReply with a corrected query in the same format.`,
      },
    ],
    onToken,
  );
  return parseNlqResponse(raw);
}
