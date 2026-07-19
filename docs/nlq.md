# Natural Language Querying (Query console)

The **Query** tab lets an analyst interrogate the loaded capture's flow table with SQL — or
plain English — **entirely in the browser**. A DuckDB-Wasm engine (lazy-loaded, ~35 MB of
same-origin wasm fetched on first use) holds the capture's flows in an in-memory table; every
query executes locally. Design + phasing: `docs/plans/2026-07-19-natural-language-querying.md`.

## What runs where

| Action | Where it runs | What leaves the device |
|---|---|---|
| SQL console (editor, bundled/saved queries, results, CSV, "Open in Flows") | In-page DuckDB-Wasm worker | **Nothing** |
| "Generate SQL" from an English question | LLM via the `ai-proxy` edge function | The **question text** you typed |
| Automatic repair round (a generated query failed) | LLM via `ai-proxy` | The failing **SQL + DuckDB error text** |

Flow records, packets, payloads, the derived summary, and the capture file are **never** sent
by this feature. The SQL itself — generated or hand-written — always executes locally.

## Enabling

- The **SQL console works for everyone, always** — it is fully local and needs no
  configuration, no account, and no network.
- The **natural-language row** appears only when the operator has enabled the AI feature
  (`ai_config.enabled` in the admin console — the same kill-switch as the AI Analyst
  summary/chat) **and** the user accepts the AI consent dialog (per-browser, one-time,
  shared with the other AI surfaces).

## The queryable table

One table, `flow`, matching the engine's canonical 31-column schema (v10 — see
`engine/crates/ppcap-core/src/columnar/schema.rs`; the browser copy is
`ui/src/lib/query/schema.ts`, drift-guarded from both sides via
`ui/src/lib/query/flow_columns.json`). Notes:

- `src_*` is the connection **initiator** (SYN sender / first packet); `dst_*` the responder.
- `start_ts`/`end_ts` are UTC `TIMESTAMP`s at **millisecond** precision (the engine's Parquet
  stores nanoseconds; the browser's normalized rows are ms — same as the Flows table).
- `category` and `severity` hold lowercase engine tokens; `ioc` flags threat-feed matches.
- Findings/incidents (summary JSON) are **not** queryable in v1 — flow metadata only.

## Safety rails on executed SQL

Three independent layers (all local):

1. **Read-only guard** (`ui/src/lib/query/guard.ts`): single statement, must start with
   `SELECT`/`WITH`, statement/keyword denylist (comment- and string-aware), and a
   `LIMIT 5000` appended when the query has no top-level LIMIT.
2. **Hardened session**: `enable_external_access = false` + `lock_configuration = true` are
   set before any user SQL, so file/network table functions (`read_parquet`, httpfs,
   `ATTACH`, …) are off at the engine level and cannot be re-enabled.
3. **Caps**: results materialize at most 5 000 rows (marked "truncated"); queries are
   cancelled in the worker after 20 s.

## Using the NL row

Type a question ("which host uploaded the most data overnight?") → **Generate SQL** streams
the model's query into the editor with a one-line `-- intent:` caption → review/edit → **Run**.
Generated SQL is never auto-run. If a generated query fails, one automatic repair round sends
the SQL + error text back to the model; after that, the query stays in the editor for manual
fixing. Questions the flow table can't answer (payload contents, packet bytes) come back as an
error rather than a hallucinated query.

## Limitations

- DuckDB SQL dialect; the six bundled queries (from `engine/crates/ppcap-core/sql/queries/`)
  are good starting points.
- One capture at a time (the active one); no cross-capture joins.
- The NL model sees the schema, not your data — it cannot know which hosts/domains exist in
  the capture until you run the query.
