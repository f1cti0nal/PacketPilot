// Post-build: emit a static HTML file per SEO route with crawlable <title>/meta/OG/JSON-LD.
// Vercel `cleanUrls` then serves dist/<slug>.html for /<slug>; the SPA renders the body.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
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
const indexHtml = readFileSync(indexPath, "utf8");
const SITE = "https://packet-pilot.vercel.app";

const esc = (s) =>
  String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

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

  let html = indexHtml
    .replace(/<title>[\s\S]*?<\/title>/, `<title>${esc(p.metaTitle)}</title>`)
    .replace(/<meta\s+name="description"[\s\S]*?>/, `<meta name="description" content="${esc(p.metaDescription)}" />`);

  const inject = `    <link rel="canonical" href="${url}" />
    <meta property="og:title" content="${esc(p.metaTitle)}" />
    <meta property="og:description" content="${esc(p.metaDescription)}" />
    <meta property="og:type" content="website" />
    <meta property="og:url" content="${url}" />
    <meta property="og:site_name" content="PacketPilot" />
    <meta name="twitter:card" content="summary" />
    <script type="application/ld+json">${JSON.stringify(softwareLd)}</script>
    <script type="application/ld+json">${JSON.stringify(faqLd)}</script>
  </head>`;
  html = html.replace("</head>", inject);

  writeFileSync(join(dist, `${p.slug}.html`), html, "utf8");
}

console.log(`gen-seo-html: generated ${pages.length} SEO pages`);
