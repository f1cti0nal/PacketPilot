import type { LegalContent } from "./types";

// Drafted June 29, 2026; rewritten July 15, 2026 for the free-product pivot (no user
// accounts, no billing — legacy account/billing data is in wind-down). The Security page
// is product-accurate and publish-ready. Privacy & Terms are review-ready TEMPLATES —
// fill the [BRACKETED] fields and have counsel review them before you rely on them publicly.

const security: LegalContent = {
  "title": "Your data never leaves your browser.",
  "subtitle": "How PacketPilot analyzes packet captures entirely client-side — and exactly what does, and does not, cross the network.",
  "lead": "PacketPilot analyzes packet captures (.pcap, .pcapng, .cap, .gz) entirely inside your browser. A Rust engine compiled to WebAssembly does the full triage on your machine — parsing packets, reconstructing flows, scoring findings — and the capture file never leaves the page. There is no server-side packet processing and no server-side packet storage. Your packets, payloads, internal IP addresses, hostnames, and credentials are never uploaded to PacketPilot's servers. This page explains precisely how that works, states exactly what is and is not transmitted, and shows you how to verify the claim yourself in under a minute.",
  "sections": [
    {
      "heading": "The promise — and why it matters for packet captures",
      "blocks": [
        {
          "p": "A packet capture is one of the most sensitive files an organization can produce. It can contain internal and private IP addresses, hostnames and your internal network topology, cleartext credentials, session tokens, and the literal payload bytes of whatever crossed the wire — file contents included. Uploading a pcap to a third-party service means handing all of that to someone else's infrastructure."
        },
        {
          "p": "PacketPilot's core promise is that this never happens. The capture file you open — and everything inside it — stays in your browser. It is never uploaded to PacketPilot's servers, never written to PacketPilot's storage, and never processed by any PacketPilot backend. The privacy boundary is the browser tab, not a contractual promise about how we handle your upload, because there is no upload."
        },
        {
          "p": "That single property is what makes PacketPilot usable on captures you could never send to a cloud analyzer: production traffic, traffic from regulated environments, traffic carrying credentials or PII, traffic from networks you are contractually or legally forbidden from exfiltrating."
        }
      ]
    },
    {
      "heading": "How it works — a Rust→WebAssembly engine in your browser",
      "blocks": [
        {
          "p": "The entire analysis pipeline is a Rust engine compiled to WebAssembly (WASM) that runs inside your browser's JavaScript sandbox. When you open a capture, the file is read by the page and handed to the WASM engine in local memory. The engine parses the packets, reassembles flows, extracts metadata and findings, and computes severity — all on your CPU, in your tab."
        },
        {
          "p": "There is no network round-trip in this path. We do not stream your packets to a server for parsing, we do not run analysis in a backend job, and we do not keep a copy. The same code that would run on a server in a cloud product runs locally here instead, so the data has nowhere to go."
        },
        {
          "bullets": [
            "Capture parsing, flow reconstruction, and threat scoring: 100% client-side WASM.",
            "No server-side packet processing of any kind.",
            "No server-side storage of captures, flows, payloads, or extracted artifacts.",
            "Results, drill-downs, and reports are rendered in the browser from the in-memory analysis."
          ]
        }
      ]
    },
    {
      "heading": "Exactly what is — and isn't — transmitted",
      "blocks": [
        {
          "p": "Whether you use the public sample or analyze your own capture, the triage transmits nothing about your capture: with enrichment off, you get the full analysis with zero capture-derived data leaving the browser. There is no account and no sign-in — the app is open to everyone, and your captures never leave the page."
        },
        {
          "p": "The only path by which any capture-derived data can reach a backend is the optional enrichment feature, and only when you explicitly opt in. Enrichment is OFF by default and requires an explicit consent action before anything is sent — no login exists or is needed."
        },
        {
          "p": "When you do opt in, what gets sent is deliberately minimal: a DERIVED SUMMARY (aggregate statistics plus finding metadata — not raw packets) and a small number of PUBLIC IP addresses and PUBLIC domains (TLS SNI hostnames). These go to PacketPilot's own Edge Functions, which proxy them to IP/domain reputation providers (AbuseIPDB, GreyNoise, VirusTotal) and/or an LLM provider for the AI Analyst feature. The operator's provider API keys live server-side as secrets and are injected by the proxy — they are never exposed to the browser."
        },
        {
          "bullets": [
            "NEVER sent, under any setting: the raw capture file, packet payloads, and private/internal IP addresses.",
            "Sent only on your explicit opt-in: a derived summary (aggregate stats + finding metadata) plus public IPs and public domains.",
            "The proxy enforces an exact host allowlist for reputation calls (api.abuseipdb.com, www.virustotal.com, api.greynoise.io) — an SSRF/key-exfil guard — and applies per-IP and global rate limits.",
            "Enrichment is OFF by default; turning it on is a deliberate, per-feature consent action."
          ]
        },
        {
          "p": "For completeness, PacketPilot has no user accounts and no billing — there is nothing to sign up for and no payment data to collect. The only data PacketPilot stores is page-view analytics, of two kinds, and neither ever includes capture data. First-party analytics record an allowlisted set of canonical route tokens (e.g. \"/\", \"/app#flows\") and a random per-session id; off-allowlist paths are dropped, so a route can never carry an IP, host, hash, or query string, and no user id is recorded because there are no users. Separately, Google Analytics measures aggregate page views — but only if you accept the cookie banner: it is off by default, loads and sets cookies only after you consent, and receives just the same page-path tokens and standard page metadata (never any capture-derived data). Legacy account and billing records from PacketPilot's retired paid era still exist server-side only until wind-down completes — see the FAQ."
        }
      ]
    },
    {
      "heading": "Compliance, air-gap, and the data boundary that isn't crossed",
      "blocks": [
        {
          "p": "Most secure-analysis tools ask you to choose between convenience (a cloud SaaS you upload to) and control (an on-prem appliance you have to deploy, patch, and secure). PacketPilot collapses that choice: because analysis runs in the browser, the convenient option already keeps the data local."
        },
        {
          "p": "With enrichment off, no capture data crosses any trust boundary — there is no data residency question to answer, no Data Processing Agreement needed for the contents of your captures, and no sub-processor that ever sees your packets. The data stays on the analyst's workstation."
        },
        {
          "bullets": [
            "No on-prem deployment required to keep captures local — the default already does that.",
            "No data boundary crossed with enrichment off: captures never leave the workstation.",
            "Air-gapped use is supported: with no opt-in enrichment, the analyzer needs no backend calls to do its job (see the FAQ for offline specifics).",
            "Sub-processors (Supabase, which hosts the operator's private admin console, the first-party analytics, and the enrichment proxy edge functions; Vercel for hosting/CDN) handle page delivery and operations — never captures. Google Analytics is used only if you accept the cookie banner, and receives page-view analytics only — never captures. Reputation providers and the AI provider are touched only for opt-in enrichment, and only ever receive the derived summary plus public IPs/domains."
          ]
        }
      ]
    },
    {
      "heading": "Verify it yourself — don't take our word",
      "blocks": [
        {
          "p": "The claim is falsifiable, and you should falsify it. Open your browser's developer tools, go to the Network tab, and watch it while you analyze a capture with enrichment off — the public sample or your own capture, no account needed. Load the capture, run the triage, click into flows and findings."
        },
        {
          "p": "You will see the page assets and the WASM engine load — and then nothing that contains your capture. There is no request that uploads the file, streams packets, or posts payload bytes. The analysis happens with no outbound request carrying your data, because the work is done locally."
        },
        {
          "bullets": [
            "Open DevTools → Network, clear it, then load and analyze a capture with enrichment disabled — the public sample or your own capture (no account needed).",
            "Confirm the capture file is never sent in any request body or upload.",
            "Turn on enrichment and watch again: now you can see exactly what leaves — a small derived-summary payload and public indicators to the proxy endpoints, and nothing more.",
            "Inspect those requests directly: no raw packets, no payloads, no private IPs."
          ]
        }
      ]
    },
    {
      "heading": "How this differs from cloud uploaders",
      "blocks": [
        {
          "p": "Cloud pcap analyzers and online sandboxes work by taking your file. You upload the capture, their servers parse and store it, and the analysis happens on their infrastructure — which means a copy of your packets, payloads, and internal addressing now lives somewhere you don't control. Many free analysis services go further and make submitted results publicly searchable, so a capture uploaded for a quick look can end up indexed and visible to anyone, including the adversary you were investigating."
        },
        {
          "p": "PacketPilot inverts that model. The engine comes to your data instead of your data going to the engine. Nothing about your capture is uploaded when you analyze, nothing is stored server-side, and nothing about your capture is ever made public. The only data that can leave — on explicit opt-in — is a derived summary plus public indicators, which is exactly the information already designed to be looked up against public threat intel."
        },
        {
          "bullets": [
            "Cloud uploader: full capture leaves your network and is stored on their servers. PacketPilot: capture never leaves the browser, never stored server-side.",
            "Cloud uploader: free tiers often publish your results. PacketPilot: your captures and results are never made public.",
            "Cloud uploader: their infrastructure sees payloads, credentials, and internal IPs. PacketPilot: those never transit any backend, ever.",
            "Cloud uploader: privacy is a policy promise about your upload. PacketPilot: privacy is enforced by architecture — there is no upload to govern."
          ]
        }
      ]
    }
  ],
  "faq": [
    {
      "q": "Is my pcap uploaded to PacketPilot?",
      "a": "No. Capture files (.pcap, .pcapng, .cap, .gz) are analyzed entirely client-side by a Rust→WebAssembly engine in your browser. The file and everything in it — packets, payloads, private IPs, hostnames, credentials, file contents — never leave the browser and are never uploaded to our servers. There is no server-side packet processing or storage. You can confirm this in your browser's Network tab."
    },
    {
      "q": "What about the AI Analyst feature — doesn't that send my data somewhere?",
      "a": "The AI feature is opt-in and off by default — no account or login is involved, because none exist. When you enable it, only a derived summary (aggregate statistics plus finding metadata — not raw packets) and a small number of public IPs and public domains are sent, via our own Edge Function proxy, to the configured LLM provider. If you use the natural-language query feature, the question text you type (and generated SQL plus its error text) is sent the same way; the SQL itself always runs locally in your browser, so flow records never leave. The raw capture, packet payloads, and private/internal IP addresses are never sent. The same rules apply to the reputation lookups (AbuseIPDB, GreyNoise, VirusTotal)."
    },
    {
      "q": "Do you store my captures?",
      "a": "No. We never store your captures, flows, payloads, or any extracted artifacts on our servers — there is no server-side storage of capture data at all. There are also no user accounts, so there is no account data to store. The only things we store are privacy-preserving first-party page-view counts, plus legacy account and billing records from PacketPilot's retired paid era (email, hashed password, optional display name, and Stripe billing metadata — never card details) that are retained only until wind-down completes and are deleted on request. None of that is derived from your captures."
    },
    {
      "q": "Can I use it offline or air-gapped?",
      "a": "Yes for the core analyzer. The triage engine runs locally in the browser and needs no backend to parse captures and produce findings, so it works without sending capture data anywhere. The only features that require network access are the optional, opt-in enrichment calls (reputation and AI), which are off by default — in an air-gapped or offline setting you simply leave those disabled and get the full local analysis."
    }
  ],
  "updated": "July 15, 2026"
};

const privacy: LegalContent = {
  "title": "Privacy Policy",
  "subtitle": "Draft for review — complete the bracketed fields and have counsel review before launch.",
  "lead": "This is a DRAFT TEMPLATE, not legal advice. It is written to match PacketPilot's actual data flows as built, so the core privacy promise — that your packet captures are analyzed entirely in your own browser and never uploaded — is stated precisely rather than as boilerplate. Fields in [BRACKETS] must be completed by the founder, and the whole document must be reviewed and adapted by qualified legal counsel for your jurisdiction(s) before publication. Effective date and legal entity are intentionally left blank.",
  "sections": [
    {
      "heading": "0. Reviewer notes (delete before publishing)",
      "blocks": [
        {
          "p": "THIS DOCUMENT REQUIRES LEGAL REVIEW BEFORE USE. It is a template that reflects how PacketPilot processes data today; it is not a substitute for advice from a qualified attorney."
        },
        {
          "bullets": [
            "Complete every [BRACKETED PLACEHOLDER]: [LEGAL ENTITY NAME], [JURISDICTION / GOVERNING LAW], [CONTACT EMAIL e.g. support@...], [EFFECTIVE DATE].",
            "Google Analytics is now integrated (consent-gated, hard opt-in — it loads and sets cookies only after the visitor accepts the cookie banner). Confirm the GA property disables Google Signals / advertising features, that data-retention and IP handling match these disclosures, put a Data Processing Agreement with Google in place, add Google (LLC) to the sub-processor list, and have counsel confirm the consent mechanism satisfies ePrivacy/GDPR for your target regions.",
            "Confirm the sub-processor list still matches reality at publish time (Supabase, Vercel, Google for Google Analytics; plus AbuseIPDB, GreyNoise, VirusTotal, and your configured AI/LLM provider for opt-in enrichment; Stripe appears only as a legacy wind-down entry).",
            "PacketPilot no longer has user accounts or billing. Confirm the legacy wind-down disclosures below (retired account records and Stripe billing metadata) match actual practice, and delete them once wind-down completes. [FOUNDER/COUNSEL: confirm the wind-down timeline and legally required retention for legacy billing records.]",
            "If you enable an AI provider whose terms allow training on inputs, disclose it explicitly here and reconsider — the enrichment payload contains public IPs/domains and derived findings.",
            "Counsel should confirm whether you act as a data controller and/or processor, whether a DPA/EU representative is needed, and whether US state laws (e.g. CCPA/CPRA) require additional disclosures.",
            "Verify retention periods below are operationally true (i.e., that analytics and audit rows are actually pruned on the stated schedule)."
          ]
        }
      ]
    },
    {
      "heading": "1. Introduction and scope",
      "blocks": [
        {
          "p": "PacketPilot (\"PacketPilot\", \"we\", \"us\") is an in-browser network packet-capture threat-triage tool operated by [LEGAL ENTITY NAME]. This Privacy Policy explains what information we do and do not handle when you use the PacketPilot website and application at https://packetpilot.app (the \"Service\"). The Service is free of charge for everyone — there are no tiers, no subscriptions, and no user accounts."
        },
        {
          "p": "PacketPilot is a solo-operated product. This policy covers the marketing site, the in-browser analyzer, the optional opt-in enrichment features, and the legacy account and billing data remaining from PacketPilot's retired paid era while it is wound down. It does not cover third-party sites you reach through external links, or the threat-intelligence and AI providers' own handling of data you choose to send them via our opt-in enrichment features, which are governed by their respective policies."
        },
        {
          "p": "By using the Service you acknowledge this policy. If you do not agree with it, please do not use the Service. The full analyzer is available to everyone anonymously — there is no account and no sign-in — and captures are processed only in your browser."
        }
      ]
    },
    {
      "heading": "2. What we do NOT collect (read this first)",
      "blocks": [
        {
          "p": "The single most important fact about PacketPilot: your packet captures never leave your browser. When you open a capture file (.pcap, .pcapng, .cap, or .gz), it is analyzed entirely on your own device by a Rust-to-WebAssembly engine running locally in your browser tab. There is no server-side packet processing and no server-side capture storage."
        },
        {
          "p": "Specifically, we never upload, receive, process, or store any of the following:"
        },
        {
          "bullets": [
            "The capture file itself — it is read in your browser and is never transmitted to PacketPilot's servers.",
            "Raw packets or packet payloads of any kind.",
            "Internal / private / RFC 1918 IP addresses from your captures.",
            "Internal hostnames, MAC addresses, or device identities derived from your captures.",
            "Credentials, cookies, tokens, or any secrets that may appear in captured traffic.",
            "Reconstructed or carved file contents from captured traffic.",
            "Full payload bodies (e.g., HTTP request/response bodies) — the engine reads protocol metadata, never the body, and none of it is sent to us."
          ]
        },
        {
          "p": "Because analysis happens locally, closing the browser tab discards the in-memory analysis. We have no copy. We cannot retrieve, share, subpoena-produce, or be breached for capture contents we never held."
        }
      ]
    },
    {
      "heading": "3. Information we DO collect",
      "blocks": [
        {
          "p": "We collect only the limited categories below, and several are optional or legacy. None of them include capture contents as described in Section 2."
        },
        {
          "p": "3.1 No user accounts. PacketPilot has no user accounts and no user-facing sign-in, and we collect no registration information of any kind. (The operator maintains a single private admin console at a separate address, with its own operator-only login; it is not part of the public Service.) Legacy account records from PacketPilot's retired paid era — an email address, a salted password hash (never the plaintext), and an optional display name — may still exist server-side. They are retained only until the wind-down of the retired era completes, are used for nothing else, and are deleted on verified request (see Section 5). [FOUNDER/COUNSEL: confirm the wind-down timeline for legacy account records and delete this clause once they are purged.]"
        },
        {
          "p": "3.2 Legacy billing metadata (no new collection). PacketPilot no longer sells anything, so we collect no billing information. During the retired paid era, payments were processed entirely by Stripe — we never saw or stored card numbers or other payment details. Limited Stripe billing metadata from that era (a Stripe customer id, subscription id, price/plan identifier, status, amount and currency, and period/renewal dates) is retained only as required for tax, accounting, and legal compliance while legacy subscriptions are wound down. [FOUNDER/COUNSEL: confirm the legally required retention scope and period for legacy billing records.]"
        },
        {
          "p": "3.3 Page-view analytics. We record privacy-preserving page views to understand product usage, using two mechanisms; neither ever includes capture data. (a) First-party analytics: for each view we store an allowlisted canonical route token only (for example \"/\", \"/app#flows\", \"/admin#dashboard\") and a random per-session id (generated in your browser and tied to no identity — there are no user accounts, so no user id exists or is recorded); this record may also include a referrer, a coarse country, and the browser user-agent string. The path is matched against a fixed allowlist and any off-list path is dropped, so a recorded path can never carry an IP address, hostname, SNI, file hash, or query string. (b) Google Analytics (consent-required): only if you accept our cookie banner, we also load Google Analytics, which sets cookies and reports your page views and standard web/device metadata to Google (LLC) for aggregate usage measurement. It is off by default, loads nothing until you consent, receives only page-path tokens and standard page metadata — never any capture-derived data — and you can decline. We use no third-party advertising pixels and do not enable cross-site ad tracking."
        },
        {
          "p": "3.4 Opt-in enrichment data (users who explicitly consent only). The enrichment features (reputation lookups and the AI Analyst) are OFF by default and require an explicit opt-in/consent action — no account or sign-in is involved. When you turn them on for a given analysis, your browser sends to our own server-side functions only: a DERIVED SUMMARY (aggregate statistics and finding metadata — not raw packets) and a small number of PUBLIC IP addresses and PUBLIC domains (such as TLS SNI hostnames). Private/internal IPs, payloads, and the raw capture are never sent. Our functions apply per-IP and global rate limits to prevent abuse, forward the data to the configured providers (see Section 6) to fetch reputation and AI analysis, then return the results to your browser."
        },
        {
          "p": "3.5 Operational and security logs. We keep a limited administrative audit log of privileged actions taken in the operator admin console, and standard infrastructure/operational logs from our hosting providers. These do not contain capture contents."
        }
      ]
    },
    {
      "heading": "4. How we use information",
      "blocks": [
        {
          "bullets": [
            "To provide and operate the Service, including remembering your preferences (which are stored locally in your browser).",
            "To measure aggregate product usage and improve the Service, using the privacy-preserving page-view analytics described in Section 3.3.",
            "To perform optional, explicitly opted-in enrichment — reputation lookups and AI analysis — on the derived summary and public indicators you choose to submit.",
            "To maintain security, prevent abuse of the enrichment proxies (per-IP and global rate limits), debug issues, and keep an audit trail of administrative actions.",
            "To wind down the legacy data from the retired paid era — retaining legacy account records and Stripe billing metadata only as long as needed for that wind-down and for legal/accounting compliance, and honoring deletion requests."
          ]
        },
        {
          "p": "We do not sell your personal information, and we do not use your data to build advertising profiles. We do not use your packet captures for anything — we never receive them."
        }
      ]
    },
    {
      "heading": "5. Legal bases (GDPR) and your rights",
      "blocks": [
        {
          "p": "Where the EU/UK GDPR applies, we rely on the following legal bases:"
        },
        {
          "bullets": [
            "Performance of a contract (Art. 6(1)(b)) — providing the Service you request when you use it.",
            "Legitimate interests (Art. 6(1)(f)) — privacy-preserving first-party analytics, security, abuse and fraud prevention, and basic operational logging, balanced against your rights.",
            "Consent (Art. 6(1)(a)) — Google Analytics and the optional, opt-in enrichment features (reputation and AI Analyst), all of which are off by default, require your explicit acceptance, and which you may decline or withdraw at any time.",
            "Legal obligation (Art. 6(1)(c)) — retaining certain legacy billing records where required by law."
          ]
        },
        {
          "p": "Subject to applicable law, you have the right to: access the personal data we hold about you (for most visitors this is nothing beyond the analytics described above — there are no accounts); correct inaccurate data; request deletion of legacy account or billing data from the retired paid era; object to or restrict certain processing; and withdraw consent to Google Analytics or enrichment at any time (which does not affect prior processing). You can use the analyzer — on the public sample or your own captures — without providing any personal data at all."
        },
        {
          "p": "There is no account to delete, because there are no accounts. If you created an account during PacketPilot's retired paid era, you can request deletion of your legacy account records and billing linkage by contacting us at [CONTACT EMAIL e.g. support@...]; we will respond to verified requests within the timeframe required by applicable law, subject to legally required retention of billing records. You also have the right to lodge a complaint with your local data protection authority. [FOUNDER/COUNSEL: confirm the deletion-request workflow for legacy records.]"
        }
      ]
    },
    {
      "heading": "6. Sub-processors",
      "blocks": [
        {
          "p": "We use the following sub-processors. Captures are never shared with any of them, because we never have your captures."
        },
        {
          "p": "Always used (infrastructure):"
        },
        {
          "bullets": [
            "Supabase — hosts the operator's private admin console (operator login only), the first-party analytics rows, and the server-side enrichment proxy functions. It never receives captures. It also still holds the legacy account records described in Section 3.1 until wind-down completes.",
            "Vercel — web hosting and content delivery (CDN) for the site and application.",
            "Google (LLC) — Google Analytics (web usage analytics). Loaded only if you accept the analytics cookie banner; it then receives page-view tokens and standard web/device metadata. It never receives captures. Consent-gated rather than strictly necessary — listed here for completeness.",
            "Stripe (legacy wind-down only) — processed payments during PacketPilot's retired paid era. No new payments are processed; the operator is winding down legacy subscriptions directly in Stripe, and we retain only the legacy billing metadata described in Section 3.2. [FOUNDER/COUNSEL: remove this entry once wind-down completes.]"
          ]
        },
        {
          "p": "Used only for opt-in enrichment (and only on the derived summary and public indicators you submit):"
        },
        {
          "bullets": [
            "AbuseIPDB — IP reputation lookups.",
            "GreyNoise — IP reputation lookups.",
            "VirusTotal — IP/domain reputation lookups.",
            "[Configured AI / LLM provider] — the AI Analyst feature. Depending on operator configuration this is an LLM provider such as Anthropic, OpenAI, OpenRouter, or a self-hosted model. The provider receives the derived summary and public indicators to generate its analysis. [Founder: name the live provider here and confirm its data-use/training terms.]"
          ]
        },
        {
          "p": "We may update this list as the Service evolves; material additions will be reflected here. Each sub-processor processes data under its own terms and privacy policy."
        }
      ]
    },
    {
      "heading": "7. Cookies and local storage",
      "blocks": [
        {
          "p": "We use first-party browser storage strictly necessary to run the Service, plus — only if you consent — Google Analytics cookies for aggregate usage measurement. We do not use cross-site advertising cookies."
        },
        {
          "bullets": [
            "A session id (a random value in browser storage) used to group your page views for first-party analytics. It is not shared across sites.",
            "Preferences such as your theme (light/dark) and UI density, stored locally in your browser so the app remembers your choices.",
            "Google Analytics cookies (e.g. _ga), set ONLY if you accept the cookie consent banner. They are used for aggregate usage analytics; if you decline, they are never set, and you can withdraw consent at any time.",
            "The public app sets no authentication cookies or tokens — there is no sign-in. An authentication session exists only on the operator's separate private admin console, for the operator's own login."
          ]
        },
        {
          "p": "Apart from the optional Google Analytics cookies above, these do not track you across other websites. Capture analysis state lives only in your browser's memory for the duration of the tab and is not persisted to our servers."
        }
      ]
    },
    {
      "heading": "8. Data retention",
      "blocks": [
        {
          "bullets": [
            "Captures and analysis: not retained by us at all — they never leave your browser (Section 2).",
            "Legacy account data (retired paid era): no new account data is collected. Legacy records are retained only until wind-down completes, and are deleted (or anonymized) earlier following a verified deletion request, subject to legal hold requirements. [FOUNDER/COUNSEL: set and confirm the wind-down completion date.]",
            "Legacy billing metadata (retired paid era): retained only as required for tax, accounting, and legal compliance ([RETENTION PERIOD, e.g. 7 years — confirm with counsel/your tax jurisdiction]); no new billing data is collected.",
            "Analytics events: retained in aggregate-oriented, low-detail form for [RETENTION PERIOD, e.g. 12 months] and then deleted or de-identified.",
            "Enrichment requests: the derived summary and public indicators are processed transiently to fulfill the lookup and are not retained by us as a persistent capture record; provider-side retention is governed by each provider.",
            "Administrative audit logs: retained for [RETENTION PERIOD] for security and accountability."
          ]
        },
        {
          "p": "[Founder/counsel: confirm each period above matches actual operational practice before publishing.]"
        }
      ]
    },
    {
      "heading": "9. International data transfers",
      "blocks": [
        {
          "p": "PacketPilot is operated from [JURISDICTION] and uses cloud sub-processors (Supabase, Vercel, the opt-in enrichment providers, and — for legacy billing wind-down only — Stripe) that may store or process data in the United States and other countries. Where personal data is transferred out of the EEA/UK, such transfers are made under appropriate safeguards (for example, the EU Standard Contractual Clauses and/or an adequacy mechanism) as offered by the relevant provider. [Founder/counsel: confirm the specific transfer mechanism for each provider and the regions of your Supabase project.]"
        }
      ]
    },
    {
      "heading": "10. Children",
      "blocks": [
        {
          "p": "The Service is intended for security and IT professionals and is not directed to children. We do not knowingly collect personal information from children under [16 — or the age set by your jurisdiction]. If you believe a child has provided us personal information, contact [CONTACT EMAIL e.g. support@...] and we will delete it."
        }
      ]
    },
    {
      "heading": "11. Changes to this policy",
      "blocks": [
        {
          "p": "We may update this policy from time to time. Material changes will be posted here with an updated effective date. Your continued use of the Service after changes take effect constitutes acceptance of the updated policy."
        }
      ]
    },
    {
      "heading": "12. Contact",
      "blocks": [
        {
          "p": "For privacy questions or to exercise your rights, contact [LEGAL ENTITY NAME] at [CONTACT EMAIL e.g. support@...]."
        },
        {
          "bullets": [
            "Data controller: [LEGAL ENTITY NAME]",
            "Contact: [CONTACT EMAIL e.g. support@...]",
            "Governing law: [JURISDICTION / GOVERNING LAW]",
            "Effective date: [EFFECTIVE DATE]",
            "Status: DRAFT TEMPLATE — requires review by qualified legal counsel before publication."
          ]
        }
      ]
    }
  ],
  "faq": [
    {
      "q": "Are my packet captures ever uploaded to PacketPilot's servers?",
      "a": "No. Capture files (.pcap/.pcapng/.cap/.gz) are analyzed entirely in your browser by a local WebAssembly engine. The file, its packets, payloads, private IPs, hostnames, credentials, and file contents never leave your device and are never stored server-side."
    },
    {
      "q": "Then what can reach PacketPilot's backend?",
      "a": "Only if you explicitly opt in to enrichment: a derived summary (aggregate stats and finding metadata, not raw packets) plus a small number of public IP addresses and public domains. These go to our own functions (which enforce per-IP and global rate limits), and are proxied to reputation providers (AbuseIPDB, GreyNoise, VirusTotal) and/or the configured AI provider. Private/internal IPs, payloads, and the raw capture are never sent, and enrichment is off by default. No account is involved — there are no accounts."
    },
    {
      "q": "Do I need an account to use PacketPilot?",
      "a": "No — there are no accounts. The full analyzer is free for everyone, on the public sample or your own captures, with no sign-in of any kind. Captures are analyzed entirely in your browser and never uploaded."
    },
    {
      "q": "What does the analytics actually record?",
      "a": "Two kinds, and neither carries capture data. First-party page views record an allowlisted canonical route token (e.g. \"/\" or \"/app#flows\") and a random per-session id (plus referrer, coarse country, and user-agent); off-allowlist paths are dropped, so a recorded path can never carry an IP, hostname, file hash, or query string. There are no user accounts, so no user id is ever recorded. Separately, if you accept the cookie banner, Google Analytics measures aggregate page views and sets cookies — it is off until you consent, receives only page-path tokens and standard page metadata, and you can decline. We use no third-party advertising pixels."
    },
    {
      "q": "Does PacketPilot store my credit card?",
      "a": "No. We don't sell anything, so we never collect payment details. (Legacy Stripe billing metadata from the retired paid era — customer/subscription ids, plan, status, and renewal dates, never card numbers — is being wound down and is retained only as required for tax and accounting compliance.)"
    },
    {
      "q": "Is this a finished, ready-to-publish policy?",
      "a": "No. It is a template that accurately reflects PacketPilot's data model, but it must be reviewed and adapted by qualified legal counsel, and every [BRACKETED PLACEHOLDER] (entity name, jurisdiction, contact email, effective date, retention periods) must be completed before use."
    }
  ],
  "updated": "July 15, 2026"
};

const terms: LegalContent = {
  "title": "Terms of Service",
  "subtitle": "Draft for review — complete the bracketed fields and have counsel review before launch.",
  "lead": "These Terms of Service (\"Terms\") are a legally binding agreement between you and [LEGAL ENTITY NAME] (\"PacketPilot,\" \"we,\" \"us,\" or \"our\") governing your access to and use of the PacketPilot website, web application, and related services (collectively, the \"Service\"), available at https://packetpilot.app and any successor URLs. PacketPilot is an in-browser network packet-capture threat-triage tool: you load a packet capture, and the analysis runs entirely inside your own web browser. By accessing or using the Service, you agree to be bound by these Terms. If you do not agree, do not use the Service. Effective date: [EFFECTIVE DATE].",
  "sections": [
    {
      "heading": "1. Acceptance of These Terms",
      "blocks": [
        {
          "p": "By accessing or using the Service, you acknowledge that you have read, understood, and agree to be bound by these Terms and by our Privacy Policy, which is incorporated here by reference. These Terms apply to all use of the Service, which is free of charge and requires no account or sign-in of any kind."
        },
        {
          "p": "If you are using the Service on behalf of an organization, you represent that you have authority to bind that organization to these Terms, and \"you\" refers to both you and that organization. If we update these Terms, your continued use after the update takes effect constitutes acceptance of the revised Terms (see \"Changes to These Terms and the Service\")."
        }
      ]
    },
    {
      "heading": "2. Description of the Service",
      "blocks": [
        {
          "p": "PacketPilot is a browser-based tool for triaging network packet captures (such as .pcap, .pcapng, .cap, and .gz files). It produces ranked, heuristic threat findings, summaries, and analyst-style reports to help you quickly understand what a capture contains."
        },
        {
          "p": "Analysis runs client-side. The capture analysis is performed entirely within your browser by a WebAssembly engine running on your own device. Your capture file and its contents — including packets, payloads, internal and private IP addresses, hostnames, credentials, and file contents — never leave your browser and are never uploaded to PacketPilot's servers. There is no server-side packet processing or storage."
        },
        {
          "bullets": [
            "Optional enrichment. If you explicitly opt in, a limited derived summary (aggregate statistics and finding metadata — not raw packets) together with a small number of public IP addresses and public domains (such as TLS SNI hostnames) may be sent to our servers, which proxy them to third-party reputation providers and/or an AI provider to add context. Private and internal IPs, payloads, and the raw capture are never sent. Enrichment is off by default and requires an explicit opt-in action; our proxies enforce per-IP and global rate limits.",
            "Free for everyone. The full Service — including analyzing your own captures and the opt-in enrichment features — is available to everyone anonymously, at no charge. No account, sign-in, or subscription exists or is required (see \"Fees\")."
          ]
        }
      ]
    },
    {
      "heading": "3. Eligibility",
      "blocks": [
        {
          "p": "There are no user accounts and no registration — the Service is open to everyone. The following eligibility requirements still apply to your use of it."
        },
        {
          "bullets": [
            "Age and capacity. You must be at least 18 years old (or the age of majority in your jurisdiction) and legally able to enter into these Terms. The Service is not directed to children."
          ]
        }
      ]
    },
    {
      "heading": "4. Acceptable Use",
      "blocks": [
        {
          "p": "You agree to use the Service lawfully and responsibly. You are solely responsible for the captures you analyze and for ensuring you have the right to analyze them."
        },
        {
          "bullets": [
            "Authorized captures only. You may only use the Service to analyze packet captures that you own or are otherwise lawfully authorized to analyze. You must not use the Service to process traffic you intercepted or captured without proper authorization or in violation of any applicable law (including wiretapping, computer-misuse, surveillance, privacy, and data-protection laws).",
            "No illegal or harmful use. You must not use the Service for any unlawful, fraudulent, infringing, or malicious purpose, or to facilitate any such activity.",
            "No abuse of the Service. You must not interfere with, disrupt, overload, or attempt to gain unauthorized access to the Service, its servers, or related systems, or circumvent any access controls or usage limits — including the per-IP and global rate limits on the enrichment and AI proxies.",
            "No reverse engineering. Except to the extent this restriction is prohibited by applicable law, you must not reverse engineer, decompile, disassemble, or attempt to derive the source code of the Service or its engine, beyond what is publicly made available.",
            "No resale or commercial redistribution. You must not resell, sublicense, rent, lease, or otherwise commercially redistribute the Service or provide it as a service to third parties, except as expressly permitted by us in writing.",
            "No misuse of enrichment. You must not use the opt-in enrichment or AI features to submit data you are not entitled to share, or in violation of the third-party providers' terms."
          ]
        },
        {
          "p": "We may investigate suspected violations and may suspend or terminate access for conduct we reasonably believe breaches these Terms or harms the Service, other users, or third parties."
        }
      ]
    },
    {
      "heading": "5. Fees",
      "blocks": [
        {
          "p": "The Service is free of charge. There are no subscription tiers, no paid plans, and no checkout — every feature is available to everyone at no cost."
        },
        {
          "bullets": [
            "No payment data. Because nothing is sold, we do not collect, store, or process any payment details.",
            "Future offerings. We may introduce optional paid offerings in the future; if we do, they will be announced with reasonable notice and governed by pricing and terms presented at that time.",
            "Legacy subscriptions. Subscriptions purchased under PacketPilot's retired paid tier are being wound down by the operator and will be cancelled before their next renewal. [FOUNDER/COUNSEL: the wind-down is a manual operator task in Stripe — confirm each legacy subscription is cancelled so this statement holds, and set the refund treatment of legacy subscribers (e.g., pro-rated refunds versus service through the end of the already-paid period) here.]"
          ]
        }
      ]
    },
    {
      "heading": "6. Intellectual Property",
      "blocks": [
        {
          "p": "The Service, including its software, WebAssembly engine, design, user interface, text, graphics, logos, and all related intellectual property, is owned by PacketPilot or its licensors and is protected by intellectual-property laws. These Terms do not transfer any ownership to you."
        },
        {
          "p": "Subject to your compliance with these Terms, we grant you a limited, personal, non-exclusive, non-transferable, revocable license to access and use the Service for its intended purpose. All rights not expressly granted are reserved. \"PacketPilot\" and associated names and logos are our marks and may not be used without our prior written permission. To the extent any portion of the Service is made available under a separate open-source or third-party license, that license governs that portion."
        }
      ]
    },
    {
      "heading": "7. Your Content",
      "blocks": [
        {
          "p": "\"Your Content\" means the packet captures you load and any data derived from them."
        },
        {
          "bullets": [
            "You retain your rights. As between you and us, you retain all rights in Your Content. We do not claim ownership of your captures or analysis results.",
            "Captures stay on your device. Because analysis runs client-side, your capture files and their contents are processed locally in your browser and are not uploaded to or stored on our servers. We cannot access your captures.",
            "Limited data you choose to send. The only capture-derived data that may reach our servers is the derived summary and the public IPs and public domains you send via opt-in enrichment, and only when you have explicitly opted in. You grant us the limited right to process and transmit that data to the relevant third-party providers solely to deliver the enrichment or AI features you requested."
          ]
        }
      ]
    },
    {
      "heading": "8. Third-Party Services and Sub-Processors",
      "blocks": [
        {
          "p": "We rely on third-party providers to operate the Service. Your use of features that depend on them is also subject to those providers' own terms and privacy policies. Captures are never shared with any sub-processor."
        },
        {
          "bullets": [
            "Infrastructure. Supabase hosts the operator's private admin console, the first-party analytics, and the server-side enrichment proxy functions; Vercel provides web hosting and content delivery (CDN). Neither ever receives captures.",
            "Legacy billing (wind-down only). Stripe processed payments for PacketPilot's retired paid tier. No new payments are processed; legacy subscriptions are being wound down, and payment details were always handled entirely by Stripe, never by us. [FOUNDER/COUNSEL: remove this bullet once wind-down completes.]",
            "Opt-in enrichment (reputation). If you opt in, AbuseIPDB, GreyNoise, and VirusTotal may receive the public IPs and public domains we proxy on your behalf to return reputation information.",
            "Opt-in enrichment (AI Analyst). If you opt in, the configured LLM/AI provider may receive the derived summary and public indicators we proxy on your behalf to generate analysis. AI outputs are subject to the disclaimers below.",
            "Analytics. We use first-party, privacy-preserving page-view counts (an allowlisted set of canonical route tokens and a random per-session ID) and — only if you accept our cookie banner — Google Analytics for aggregate usage measurement. Neither includes any capture data; Google Analytics is off until you consent and sets cookies only then. We do not use third-party advertising pixels."
          ]
        },
        {
          "p": "We are not responsible for the acts, omissions, content, or availability of third-party services, and your dealings with them are governed by their respective terms."
        }
      ]
    },
    {
      "heading": "9. Disclaimers — Automated Triage, No Warranty",
      "blocks": [
        {
          "p": "PLEASE READ THIS SECTION CAREFULLY. PacketPilot provides automated, heuristic triage. It applies rules and heuristics to surface potential indicators and prioritize where to look. It does not, and cannot, guarantee that it will detect every threat or that its findings are complete, correct, or free from false positives or false negatives."
        },
        {
          "bullets": [
            "Not a substitute for expert analysis. The Service is a triage aid, not professional security, legal, compliance, or incident-response advice. It does not replace expert human analysis or qualified professional judgment.",
            "You are responsible for verification. You are solely responsible for independently reviewing, verifying, and validating any findings before relying on or acting on them. Do not treat a finding (or the absence of a finding) as conclusive.",
            "AI and reputation outputs may be wrong. Outputs from the AI Analyst and from third-party reputation providers are probabilistic or sourced from third parties, and may be inaccurate, incomplete, or outdated.",
            "Provided \"as is.\" To the maximum extent permitted by applicable law, the Service is provided \"AS IS\" and \"AS AVAILABLE,\" without warranties of any kind, whether express, implied, or statutory — including any implied warranties of merchantability, fitness for a particular purpose, accuracy, non-infringement, and any warranty that the Service will be uninterrupted, secure, or error-free."
          ]
        },
        {
          "p": "Some jurisdictions do not allow the exclusion of certain warranties, so some of the above exclusions may not apply to you. In that case, such warranties are limited to the minimum extent permitted by applicable law."
        }
      ]
    },
    {
      "heading": "10. Limitation of Liability",
      "blocks": [
        {
          "p": "To the maximum extent permitted by applicable law, in no event will PacketPilot, its owner(s), or its suppliers be liable for any indirect, incidental, special, consequential, exemplary, or punitive damages, or for any loss of profits, revenue, data, goodwill, or other intangible losses, arising out of or relating to your use of (or inability to use) the Service, any findings or outputs it produces, or any reliance on them — even if advised of the possibility of such damages."
        },
        {
          "p": "To the maximum extent permitted by applicable law, our total aggregate liability arising out of or relating to these Terms or the Service will not exceed the greater of (a) the total amounts you paid to us for the Service in the twelve (12) months immediately preceding the event giving rise to the claim, or (b) [CURRENCY/AMOUNT — e.g., USD 100]. [FOUNDER/COUNSEL: the Service is currently free of charge, so clause (a) will ordinarily be zero and the fixed floor in (b) will govern — confirm the amount.] Some jurisdictions do not allow certain limitations of liability, so some of the above may not apply to you, and nothing in these Terms limits liability that cannot be limited under applicable law."
        }
      ]
    },
    {
      "heading": "11. Indemnification",
      "blocks": [
        {
          "p": "To the maximum extent permitted by applicable law, you agree to indemnify, defend, and hold harmless PacketPilot and its owner(s) from and against any claims, liabilities, damages, losses, and expenses (including reasonable legal fees) arising out of or related to: (a) your use of the Service; (b) your captures or the data you analyze or send for enrichment, including any claim that you lacked authorization to capture or analyze that traffic; (c) your violation of these Terms or any applicable law; or (d) your infringement of any third-party right."
        }
      ]
    },
    {
      "heading": "12. Termination and Suspension",
      "blocks": [
        {
          "p": "You may stop using the Service at any time; because there are no user accounts, there is nothing to close or cancel. If you hold a legacy subscription from the retired paid tier, its wind-down is described under \"Fees.\""
        },
        {
          "p": "We may suspend or terminate your access to the Service (in whole or in part), with or without notice, if we reasonably believe you have violated these Terms, if required to comply with law, or to protect the Service, other users, or third parties. Upon termination, your license to use the Service ends. Provisions that by their nature should survive termination — including intellectual property, disclaimers, limitation of liability, indemnification, and governing law — will survive."
        }
      ]
    },
    {
      "heading": "13. Changes to These Terms and the Service",
      "blocks": [
        {
          "p": "We may modify these Terms from time to time. When we do, we will update the \"Effective date\" and, for material changes, provide reasonable notice (for example, by posting in the Service). Changes take effect when posted or on the date stated in the notice. Your continued use of the Service after changes take effect constitutes acceptance. If you do not agree to the updated Terms, you must stop using the Service."
        },
        {
          "p": "We may also add, change, suspend, or discontinue features of the Service at any time. We will use reasonable efforts to provide notice of material adverse changes to the Service."
        }
      ]
    },
    {
      "heading": "14. Governing Law and Disputes",
      "blocks": [
        {
          "p": "These Terms and any dispute arising out of or relating to them or the Service are governed by the laws of [JURISDICTION / GOVERNING LAW], without regard to its conflict-of-laws rules. You and we agree to submit to the exclusive jurisdiction of the courts located in [JURISDICTION / GOVERNING LAW] to resolve any dispute, except where applicable law gives you the right to bring proceedings in another forum. [FOUNDER/COUNSEL: consider whether to add an informal-resolution step, arbitration clause, or class-action waiver appropriate to [JURISDICTION] and your customer base.]"
        }
      ]
    },
    {
      "heading": "15. General",
      "blocks": [
        {
          "bullets": [
            "Entire agreement. These Terms, together with the Privacy Policy, are the entire agreement between you and us regarding the Service and supersede prior agreements on that subject.",
            "Severability. If any provision is found unenforceable, the remaining provisions remain in full force, and the unenforceable provision will be modified to the minimum extent necessary to make it enforceable.",
            "No waiver. Our failure to enforce any provision is not a waiver of our right to do so later.",
            "Assignment. You may not assign these Terms without our prior written consent. We may assign them in connection with a merger, acquisition, or sale of assets.",
            "Force majeure. We are not liable for any failure or delay caused by events beyond our reasonable control."
          ]
        }
      ]
    },
    {
      "heading": "16. Contact",
      "blocks": [
        {
          "p": "Questions about these Terms? Contact us at [CONTACT EMAIL] or [LEGAL ENTITY NAME], [REGISTERED ADDRESS — optional]."
        },
        {
          "p": "Reviewer note: This document is a template intended for founder and counsel review before publication. Complete all bracketed placeholders ([LEGAL ENTITY NAME], [JURISDICTION / GOVERNING LAW], [CONTACT EMAIL], [EFFECTIVE DATE], [CURRENCY/AMOUNT], and any marked decisions) and have qualified legal counsel review it for your jurisdiction and business before relying on it. It is not legal advice."
        }
      ]
    }
  ],
  "faq": [
    {
      "q": "Do you upload or store my packet captures?",
      "a": "No. Analysis runs entirely client-side in your browser via a WebAssembly engine. Your capture file and its contents — packets, payloads, private IPs, hostnames, credentials, file contents — never leave your browser and are never uploaded to or stored on our servers."
    },
    {
      "q": "Do I need an account to use PacketPilot?",
      "a": "No — there are no accounts and no sign-in. Every feature, including analyzing your own captures, is free for everyone. Your captures are analyzed entirely in your browser."
    },
    {
      "q": "What is opt-in enrichment, and what data does it send?",
      "a": "If you explicitly opt in, a derived summary (aggregate statistics and finding metadata — not raw packets) plus a small number of public IPs and public domains may be sent to our servers, which apply rate limits and proxy them to reputation providers (AbuseIPDB, GreyNoise, VirusTotal) and/or an AI provider. Private/internal IPs, payloads, and the raw capture are never sent. It is off by default, and no account is required."
    },
    {
      "q": "Is PacketPilot really free?",
      "a": "Yes. Every feature is available to everyone at no charge, with no account and no billing — we never collect payment details. Subscriptions from the retired paid tier are being wound down and will not renew."
    },
    {
      "q": "Can I rely on the findings as definitive?",
      "a": "No. PacketPilot provides automated, heuristic triage and is provided \"as is\" with no warranty that findings are complete or accurate. It is not a substitute for expert analysis or professional security advice, and you are responsible for independently verifying any finding before acting on it."
    },
    {
      "q": "What can I use the Service to analyze?",
      "a": "Only captures you own or are otherwise lawfully authorized to analyze. You must not process traffic you captured without authorization or in violation of applicable wiretapping, computer-misuse, surveillance, privacy, or data-protection laws."
    }
  ],
  "updated": "July 15, 2026"
};

export const LEGAL_PAGES: Record<"/security" | "/privacy" | "/terms", LegalContent> = {
  "/security": security,
  "/privacy": privacy,
  "/terms": terms,
};
