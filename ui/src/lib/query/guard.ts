/**
 * Read-only guard for SQL destined for the in-browser DuckDB (see the NLQ plan,
 * docs/plans/2026-07-19-natural-language-querying.md §3.2). Generated or
 * hand-typed SQL is untrusted input; this is one of three defense layers
 * (alongside `SET enable_external_access = false` + `SET lock_configuration =
 * true` at engine init, and the row/time caps in engine.ts).
 *
 * The scanner is comment- and string-aware (single quotes with '' escaping,
 * double-quoted identifiers, line comments, block comments with nesting), so
 * denied words inside string literals or comments do not trip the guard.
 * Dollar-quoted strings ($$…$$) are NOT recognized — their contents get
 * tokenized, which can only over-block (a false deny), never under-block.
 */

/** Appended when a statement has no top-level LIMIT of its own. */
export const DEFAULT_ROW_LIMIT = 5000;

export type GuardResult =
  | { ok: true; sql: string; limitApplied: boolean }
  | { ok: false; reason: string };

/**
 * Statement/keyword denylist (exact word-token match, case-insensitive). Most
 * of these are already unreachable behind the SELECT/WITH prefix check; keeping
 * them banned as bare tokens is belt-and-braces against expression-embedded
 * forms and future dialect surprises.
 */
const DENIED_WORDS = new Set([
  "alter",
  "attach",
  "begin",
  "call",
  "checkpoint",
  "commit",
  "copy",
  "create",
  "delete",
  "detach",
  "drop",
  "export",
  "force",
  "grant",
  "import",
  "insert",
  "install",
  "load",
  "pragma",
  "reset",
  "revoke",
  "rollback",
  "set",
  "transaction",
  "truncate",
  "update",
  "use",
  "vacuum",
]);

interface WordToken {
  word: string;
  /** Parenthesis depth at the token; 0 = top level of the statement. */
  depth: number;
}

interface Statement {
  /** Statement text with comments collapsed to a single space. */
  text: string;
  tokens: WordToken[];
}

const WORD_CHAR = /[A-Za-z0-9_$]/;

/** Split on `;` outside strings/comments, tokenizing bare words as we go. */
function scan(src: string): Statement[] {
  const statements: Statement[] = [{ text: "", tokens: [] }];
  let depth = 0;
  let word = "";
  let i = 0;

  const current = () => statements[statements.length - 1];
  const flushWord = () => {
    if (word.length > 0) {
      current().tokens.push({ word: word.toLowerCase(), depth });
      word = "";
    }
  };

  while (i < src.length) {
    const c = src[i];
    const pair = src.slice(i, i + 2);

    if (pair === "--") {
      flushWord();
      while (i < src.length && src[i] !== "\n") i++;
      current().text += " ";
      continue;
    }
    if (pair === "/*") {
      // Block comments nest (Postgres-style, which DuckDB follows).
      flushWord();
      let nest = 1;
      i += 2;
      while (i < src.length && nest > 0) {
        if (src.slice(i, i + 2) === "/*") {
          nest++;
          i += 2;
        } else if (src.slice(i, i + 2) === "*/") {
          nest--;
          i += 2;
        } else {
          i++;
        }
      }
      current().text += " ";
      continue;
    }
    if (c === "'" || c === '"') {
      // Quoted string/identifier; a doubled quote is an escaped quote, not the end.
      flushWord();
      let out = c;
      i++;
      while (i < src.length) {
        if (src[i] === c) {
          if (src[i + 1] === c) {
            out += c + c;
            i += 2;
            continue;
          }
          out += c;
          i++;
          break;
        }
        out += src[i];
        i++;
      }
      // An unterminated quote swallows the rest; DuckDB will reject it with a
      // parse error, which is the right user-facing message.
      current().text += out;
      continue;
    }
    if (c === ";") {
      flushWord();
      statements.push({ text: "", tokens: [] });
      i++;
      continue;
    }
    if (c === "(") {
      flushWord();
      depth++;
      current().text += c;
      i++;
      continue;
    }
    if (c === ")") {
      flushWord();
      depth = Math.max(0, depth - 1);
      current().text += c;
      i++;
      continue;
    }
    if (WORD_CHAR.test(c)) {
      word += c;
      current().text += c;
      i++;
      continue;
    }
    flushWord();
    current().text += c;
    i++;
  }
  flushWord();

  return statements
    .map((s) => ({ text: s.text.trim(), tokens: s.tokens }))
    .filter((s) => s.text.length > 0);
}

/**
 * Validate `input` as a single read-only SELECT/WITH statement. On success,
 * returns the statement to execute (comments collapsed; ` LIMIT 5000` appended
 * when the statement has no top-level LIMIT — reported via `limitApplied`).
 */
export function guardSql(input: string): GuardResult {
  const statements = scan(input);

  if (statements.length === 0) {
    return { ok: false, reason: "Empty query." };
  }
  if (statements.length > 1) {
    return { ok: false, reason: "Only a single statement is allowed per query." };
  }

  const stmt = statements[0];
  if (!/^(select|with)\b/i.test(stmt.text)) {
    return {
      ok: false,
      reason: "Only read-only SELECT (or WITH … SELECT) queries are allowed.",
    };
  }

  const denied = stmt.tokens.find((t) => DENIED_WORDS.has(t.word));
  if (denied) {
    return {
      ok: false,
      reason: `"${denied.word.toUpperCase()}" is not allowed — queries are read-only.`,
    };
  }

  const hasTopLevelLimit = stmt.tokens.some(
    (t) => t.word === "limit" && t.depth === 0,
  );
  const sql = hasTopLevelLimit ? stmt.text : `${stmt.text} LIMIT ${DEFAULT_ROW_LIMIT}`;
  return { ok: true, sql, limitApplied: !hasTopLevelLimit };
}
