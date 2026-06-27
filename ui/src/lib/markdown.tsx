import type { ReactNode } from "react";

// A tiny, dependency-free Markdown renderer for the subset LLMs emit in the AI Analyst output:
// headings, bold, italic, inline code, unordered/ordered lists, and paragraphs. It produces React
// elements (never dangerouslySetInnerHTML), so model text is escaped by React — no XSS. It also
// degrades gracefully on the partial markdown seen mid-stream (an unclosed `**` renders as literal
// text until its closer arrives).

// ── inline: bold / italic / code ──────────────────────────────────────────────
// Ordered by precedence: code first (so markers inside `code` stay literal), then bold, then italic.
const INLINE: { re: RegExp; tag: "code" | "strong" | "em" }[] = [
  { re: /`([^`]+)`/, tag: "code" },
  { re: /\*\*([^*]+?)\*\*/, tag: "strong" },
  { re: /__([^_]+?)__/, tag: "strong" },
  { re: /\*(\S[^*]*?)\*/, tag: "em" }, // leading \S avoids matching "5 * 3"
  { re: /_(\S[^_]*?)_/, tag: "em" },
];

function inline(text: string, keyBase: string): ReactNode[] {
  const out: ReactNode[] = [];
  let rest = text;
  let k = 0;
  while (rest.length) {
    let best: { idx: number; len: number; inner: string; tag: string } | null = null;
    for (const { re, tag } of INLINE) {
      const m = re.exec(rest);
      if (m && (best === null || m.index < best.idx)) {
        best = { idx: m.index, len: m[0].length, inner: m[1], tag };
      }
    }
    if (!best) {
      out.push(rest);
      break;
    }
    if (best.idx > 0) out.push(rest.slice(0, best.idx));
    const key = `${keyBase}-${k++}`;
    if (best.tag === "code") {
      out.push(
        <code key={key} className="rounded bg-[var(--color-surface-2)] px-1 font-mono text-[0.95em]">{best.inner}</code>,
      );
    } else if (best.tag === "strong") {
      out.push(<strong key={key}>{best.inner}</strong>);
    } else {
      out.push(<em key={key}>{best.inner}</em>);
    }
    rest = rest.slice(best.idx + best.len);
  }
  return out;
}

const HEADING = /^(#{1,6})\s+(.*)$/;
const LIST_ITEM = /^\s*([-*+]|\d+[.)])\s+(.*)$/;

/** Render a Markdown string as formatted React content (block-level + inline). */
export function Markdown({ text, className }: { text: string; className?: string }): ReactNode {
  const lines = text.replace(/\r\n/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let para: string[] = [];
  let list: { ordered: boolean; items: string[] } | null = null;
  let key = 0;

  const flushPara = () => {
    if (para.length) {
      blocks.push(
        <p key={`p-${key++}`} className="whitespace-pre-wrap break-words">{inline(para.join(" "), `p-${key}`)}</p>,
      );
      para = [];
    }
  };
  const flushList = () => {
    if (list) {
      const items = list.items.map((it, i) => <li key={i}>{inline(it, `li-${key}-${i}`)}</li>);
      blocks.push(
        list.ordered
          ? <ol key={`ol-${key++}`} className="list-decimal space-y-0.5 pl-5">{items}</ol>
          : <ul key={`ul-${key++}`} className="list-disc space-y-0.5 pl-5">{items}</ul>,
      );
      list = null;
    }
  };

  for (const raw of lines) {
    const line = raw.trimEnd();
    if (line.trim() === "") {
      flushPara();
      flushList();
      continue;
    }
    const h = HEADING.exec(line);
    if (h) {
      flushPara();
      flushList();
      blocks.push(
        <p key={`h-${key++}`} className="mt-1 font-medium text-[var(--color-text)]">{inline(h[2], `h-${key}`)}</p>,
      );
      continue;
    }
    const li = LIST_ITEM.exec(line);
    if (li) {
      flushPara();
      const ordered = /\d/.test(li[1]);
      if (!list || list.ordered !== ordered) {
        flushList();
        list = { ordered, items: [] };
      }
      list.items.push(li[2]);
      continue;
    }
    flushList();
    para.push(line.trim());
  }
  flushPara();
  flushList();

  return <div className={className ? `flex flex-col gap-2 ${className}` : "flex flex-col gap-2"}>{blocks}</div>;
}

export default Markdown;
