// Post-build: emit a static HTML file per SEO/blog route with crawlable <title>/meta/OG/JSON-LD.
// Vercel `cleanUrls` then serves dist/<slug>.html for /<slug>; the SPA renders the body.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = dirname(dirname(fileURLToPath(import.meta.url))); // ui/
const dist = join(root, "dist");
const indexPath = join(dist, "index.html");
if (!existsSync(indexPath)) {
  console.error("gen-seo-html: dist/index.html not found — run `vite build` first");
  process.exit(1);
}

const pages = JSON.parse(readFileSync(join(root, "src", "seo", "pages.json"), "utf8"));
const posts = JSON.parse(readFileSync(join(root, "src", "blog", "posts.json"), "utf8"));
const indexHtml = readFileSync(indexPath, "utf8");
const SITE = "https://packetpilot.app";

const esc = (s) =>
  String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

// Overwrite a base meta tag's value in place (matches single- or multi-line forms) so each
// page has exactly one og:/twitter: tag — never a duplicate of the base homepage one.
const setMeta = (h, attr, key, value) =>
  h.replace(
    new RegExp(`<meta\\s+${attr}="${key}"[\\s\\S]*?/>`),
    `<meta ${attr}="${key}" content="${esc(value)}" />`,
  );

// Rewrite the base index.html head with this route's title/description/canonical/og/twitter
// (the shared og:image, og:site_name/type, and twitter:card are inherited) and inject JSON-LD.
function renderHead({ title, description, url, jsonLd }) {
  let html = indexHtml
    .replace(/<title>[\s\S]*?<\/title>/, `<title>${esc(title)}</title>`)
    .replace(/<meta\s+name="description"[\s\S]*?\/>/, `<meta name="description" content="${esc(description)}" />`)
    .replace(/<link rel="canonical"[^>]*>/, `<link rel="canonical" href="${url}" />`);
  html = setMeta(html, "property", "og:title", title);
  html = setMeta(html, "property", "og:description", description);
  html = setMeta(html, "property", "og:url", url);
  html = setMeta(html, "name", "twitter:title", title);
  html = setMeta(html, "name", "twitter:description", description);
  const scripts = jsonLd
    .map((o) => `    <script type="application/ld+json">${JSON.stringify(o)}</script>`)
    .join("\n");
  return html.replace("</head>", `${scripts}\n  </head>`);
}

// ── SEO tool pages ────────────────────────────────────────────────────────────
for (const p of pages) {
  const url = `${SITE}/${p.slug}`;
  const softwareLd = {
    "@context": "https://schema.org",
    "@type": "SoftwareApplication",
    name: "PacketPilot",
    applicationCategory: "SecurityApplication",
    operatingSystem: "Web browser",
    offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
    description: p.metaDescription,
    url,
  };
  const faqLd = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: (p.faq ?? []).map((f) => ({
      "@type": "Question",
      name: f.q,
      acceptedAnswer: { "@type": "Answer", text: f.a },
    })),
  };
  writeFileSync(
    join(dist, `${p.slug}.html`),
    renderHead({ title: p.metaTitle, description: p.metaDescription, url, jsonLd: [softwareLd, faqLd] }),
    "utf8",
  );
}

// ── Blog: index + one page per post ───────────────────────────────────────────
mkdirSync(join(dist, "blog"), { recursive: true });
const blogUrl = `${SITE}/blog`;
writeFileSync(
  join(dist, "blog.html"),
  renderHead({
    title: "The PacketPilot Blog — Network Forensics Notes",
    description:
      "Network-forensics teardowns and detection notes from PacketPilot — packet captures analyzed in the browser, nothing uploaded.",
    url: blogUrl,
    jsonLd: [{ "@context": "https://schema.org", "@type": "Blog", name: "The PacketPilot Blog", url: blogUrl }],
  }),
  "utf8",
);
for (const post of posts) {
  const url = `${SITE}/blog/${post.slug}`;
  const postingLd = {
    "@context": "https://schema.org",
    "@type": "BlogPosting",
    headline: post.title,
    description: post.metaDescription,
    datePublished: post.date,
    dateModified: post.date,
    author: { "@type": "Organization", name: post.author || "PacketPilot" },
    publisher: { "@type": "Organization", name: "PacketPilot" },
    image: `${SITE}/og.png`,
    mainEntityOfPage: url,
    url,
    keywords: (post.tags ?? []).join(", "),
  };
  writeFileSync(
    join(dist, "blog", `${post.slug}.html`),
    renderHead({ title: post.metaTitle, description: post.metaDescription, url, jsonLd: [postingLd] }),
    "utf8",
  );
}

// sitemap.xml — public, indexable routes (marketing + SEO pages + blog).
// /admin and /account are intentionally excluded (non-public / authed).
const STATIC_ROUTES = ["", "app", "pricing", "security", "privacy", "terms", "blog"];
const routes = [
  ...STATIC_ROUTES,
  ...pages.map((p) => p.slug),
  ...posts.map((post) => `blog/${post.slug}`),
];
const sitemap =
  `<?xml version="1.0" encoding="UTF-8"?>\n` +
  `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
  routes.map((r) => `  <url><loc>${SITE}/${r}</loc></url>`).join("\n") +
  `\n</urlset>\n`;
writeFileSync(join(dist, "sitemap.xml"), sitemap, "utf8");

writeFileSync(
  join(dist, "robots.txt"),
  `User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /account\n\nSitemap: ${SITE}/sitemap.xml\n`,
  "utf8",
);

console.log(
  `gen-seo-html: generated ${pages.length} SEO pages + ${posts.length} blog post(s) + sitemap.xml + robots.txt`,
);
