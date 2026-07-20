import { useEffect } from "react";
import { ArrowLeft, Radar } from "lucide-react";
import { ThemeToggle } from "../cockpit/ThemeToggle";
import { BlogIndex } from "./BlogIndex";
import { BlogPost } from "./BlogPost";
import { blogBySlug } from "./registry";

const INDEX_TITLE = "The PacketPilot Blog — Network Forensics Notes";
const INDEX_DESC =
  "Network-forensics teardowns and detection notes from PacketPilot — packet captures analyzed in the browser, nothing uploaded.";

/** Public /blog shell. Renders the index at /blog and a post at /blog/<slug>. Per-route
 *  <title>/meta are baked into static HTML at build time (scripts/gen-seo-html.mjs); this
 *  also sets them client-side for dev + SPA navigation, mirroring the SEO ToolApp. */
export function BlogApp() {
  const path = window.location.pathname.replace(/\/+$/, "");
  const isIndex = path === "/blog";
  const slug = isIndex ? "" : path.replace(/^\/blog\//, "");
  const post = isIndex ? undefined : blogBySlug[slug];

  useEffect(() => {
    document.title = isIndex ? INDEX_TITLE : post ? post.metaTitle : "Not found | PacketPilot Blog";
    const desc = isIndex ? INDEX_DESC : post?.metaDescription;
    if (!desc) return;
    let m = document.querySelector('meta[name="description"]');
    if (!m) {
      m = document.createElement("meta");
      m.setAttribute("name", "description");
      document.head.appendChild(m);
    }
    m.setAttribute("content", desc);
  }, [isIndex, post]);

  return (
    <div className="min-h-screen bg-[var(--color-bg)] text-[var(--color-text)]">
      <header className="flex h-14 items-center gap-3 border-b border-[var(--color-border)] bg-[var(--color-surface)] px-4">
        <a href="/" aria-label="Back to home" className="flex items-center gap-2 text-[var(--color-text-dim)] hover:text-[var(--color-text)]">
          <ArrowLeft size={16} aria-hidden />
          <span
            className="flex h-7 w-7 items-center justify-center rounded-[var(--r-tile)]"
            style={{ background: "color-mix(in srgb, var(--color-accent) 16%, transparent)" }}
          >
            <Radar size={16} style={{ color: "var(--color-accent)" }} aria-hidden />
          </span>
          <span className="font-display text-[15px] font-medium tracking-tight">PacketPilot</span>
        </a>
        <div className="ml-auto flex items-center gap-3">
          <a href="/blog" className="text-xs text-[var(--color-text-dim)] hover:text-[var(--color-text)]">Blog</a>
          <ThemeToggle />
        </div>
      </header>

      {isIndex ? (
        <BlogIndex />
      ) : post ? (
        <BlogPost post={post} />
      ) : (
        <div className="mx-auto max-w-3xl px-4 py-20 text-center">
          <p className="text-[var(--color-text-dim)]">That post doesn't exist.</p>
          <a href="/blog" className="mt-2 inline-block text-sm text-[var(--color-accent-strong)]">All posts</a>
        </div>
      )}

      <footer className="border-t border-[var(--color-border)] px-4 py-6 text-center">
        <nav className="flex flex-wrap justify-center gap-4 t-tag text-[var(--color-text-faint)]">
          <a href="/blog" className="hover:text-[var(--color-text-dim)]">Blog</a>
          <a href="/app" className="hover:text-[var(--color-text-dim)]">Launch app</a>
          <a href="/security" className="hover:text-[var(--color-text-dim)]">Security</a>
        </nav>
      </footer>
    </div>
  );
}

export default BlogApp;
