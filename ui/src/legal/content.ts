import type { LegalContent } from "./types";

// Drafted June 29, 2026. The Security page is product-accurate and publish-ready.
// Privacy & Terms are review-ready TEMPLATES — fill the [BRACKETED] fields and have
// counsel review them before you rely on them publicly.

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
          "p": "Analyzing a capture transmits nothing about that capture. Signing in authenticates your identity — it never sends us your capture: even while logged in, you open a file and get the full triage with zero capture-derived data leaving the browser. Using the analyzer on your own capture requires a free account (a bundled sample capture can be previewed without one), but the account system never receives your packets."
        },
        {
          "p": "The only path by which any capture-derived data can reach a backend is the optional enrichment feature, and only for a logged-in user who explicitly opts in. Enrichment is OFF by default and requires both a login and an explicit consent action before anything is sent."
        },
        {
          "p": "When you do opt in, what gets sent is deliberately minimal: a DERIVED SUMMARY (aggregate statistics plus finding metadata — not raw packets) and a small number of PUBLIC IP addresses and PUBLIC domains (TLS SNI hostnames). These go to PacketPilot's own Edge Functions, which proxy them to IP/domain reputation providers (AbuseIPDB, GreyNoise, VirusTotal) and/or an LLM provider for the AI Analyst feature. The operator's provider API keys live server-side as secrets and are injected by the proxy — they are never exposed to the browser."
        },
        {
          "bullets": [
            "NEVER sent, under any setting: the raw capture file, packet payloads, and private/internal IP addresses.",
            "Sent only on explicit opt-in by a logged-in user: a derived summary (aggregate stats + finding metadata) plus public IPs and public domains.",
            "The proxy enforces an exact host allowlist for reputation calls (api.abuseipdb.com, www.virustotal.com, api.greynoise.io) — an SSRF/key-exfil guard — and requires a valid login.",
            "Enrichment is OFF by default; turning it on is a deliberate, per-feature consent action."
          ]
        },
        {
          "p": "For completeness, the only other data PacketPilot ever stores is account and billing metadata, none of which is derived from your captures. Accounts (optional) hold an email and hashed password via Supabase Auth, plus an optional display name and avatar. Billing is handled by Stripe — PacketPilot stores only a Stripe customer id, subscription id, status, price, and renewal date; card and payment details are handled entirely by Stripe and never touch PacketPilot's systems. Analytics are first-party page-view counts only: an allowlisted set of canonical route tokens (e.g. \"/\", \"/app#flows\"), a random per-session id, and, if logged in, the user id. Off-allowlist paths are dropped, so a route can never carry an IP, host, hash, or query string. No capture data, no third-party ad or tracking pixels, no cross-site cookies."
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
          "p": "Because analysis is client-side, no capture data crosses any trust boundary — there is no data residency question to answer, no Data Processing Agreement needed for the contents of your captures, and no sub-processor that ever sees your packets. Signing in authenticates you but never sends us your capture, so this holds whether or not you are logged in. The data stays on the analyst's workstation."
        },
        {
          "bullets": [
            "No on-prem deployment required to keep captures local — the default already does that.",
            "No data boundary crossed by the analysis: captures never leave the workstation, signed in or not.",
            "The analysis engine needs no backend to do its job — with opt-in enrichment off, no capture-derived data leaves the browser (the hosted app does require sign-in; see the FAQ).",
            "Sub-processors (Supabase for auth/database/storage, Stripe for payments, Vercel for hosting/CDN) handle accounts, billing, and page delivery — never captures. Reputation providers and the AI provider are touched only for opt-in enrichment, and only ever receive the derived summary plus public IPs/domains."
          ]
        }
      ]
    },
    {
      "heading": "Verify it yourself — don't take our word",
      "blocks": [
        {
          "p": "The claim is falsifiable, and you should falsify it. Open your browser's developer tools, go to the Network tab, and watch it while you analyze a capture with enrichment off. Load your pcap, run the triage, click into flows and findings. You will see sign-in and session traffic, but nothing that carries your capture."
        },
        {
          "p": "You will see the page assets and the WASM engine load — and then nothing that contains your capture. There is no request that uploads the file, streams packets, or posts payload bytes. The analysis happens with no outbound request carrying your data, because the work is done locally."
        },
        {
          "bullets": [
            "Open DevTools → Network, clear it, then load and analyze a capture with enrichment disabled — signed in, or via the anonymous sample capture.",
            "Confirm the capture file is never sent in any request body or upload.",
            "Turn on enrichment as a logged-in user and watch again: now you can see exactly what leaves — a small derived-summary payload and public indicators to the proxy endpoints, and nothing more.",
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
          "p": "PacketPilot inverts that model. The engine comes to your data instead of your data going to the engine. Nothing about your capture is uploaded during analysis, nothing is stored server-side, and nothing about your capture is ever made public. The only data that can leave — on explicit opt-in — is a derived summary plus public indicators, which is exactly the information already designed to be looked up against public threat intel."
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
      "a": "The AI feature is opt-in, requires a login, and is off by default. When you enable it, only a derived summary (aggregate statistics plus finding metadata — not raw packets) and a small number of public IPs and public domains are sent, via our own Edge Function proxy, to the configured LLM provider. The raw capture, packet payloads, and private/internal IP addresses are never sent. The same rules apply to the reputation lookups (AbuseIPDB, GreyNoise, VirusTotal)."
    },
    {
      "q": "Do you store my captures?",
      "a": "No. We never store your captures, flows, payloads, or any extracted artifacts on our servers — there is no server-side storage of capture data at all. The only things we store are account metadata (email, hashed password, optional display name/avatar), Stripe billing metadata (customer/subscription id, status, price, renewal date — never card details), and privacy-preserving first-party page-view counts. None of that is derived from your captures."
    },
    {
      "q": "Can I use it offline or air-gapped?",
      "a": "The triage engine runs locally in your browser and needs no backend to parse captures or produce findings — the analysis itself never sends your capture anywhere. On the hosted app at packetpilot.app you first sign in with a free account, which does require network access. Opt-in enrichment (reputation and AI) is the only feature that transmits anything derived from a capture, and it is off by default. [Founder/counsel: if an offline or self-hosted build without accounts is offered for air-gapped use, describe it here.]"
    }
  ],
  "updated": "July 2, 2026"
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
            "Confirm the sub-processor list still matches reality at publish time (Supabase, Stripe, Vercel; plus AbuseIPDB, GreyNoise, VirusTotal, and your configured AI/LLM provider for opt-in enrichment).",
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
          "p": "PacketPilot (\"PacketPilot\", \"we\", \"us\") is an in-browser network packet-capture threat-triage tool operated by [LEGAL ENTITY NAME]. This Privacy Policy explains what information we do and do not handle when you use the PacketPilot website and application at https://packetpilot.app (the \"Service\"), including the free tier and the paid Pro subscription ($19/month or $190/year)."
        },
        {
          "p": "PacketPilot is a solo-operated product. This policy covers the marketing site, the in-browser analyzer, optional user accounts, billing, and the optional logged-in enrichment features. It does not cover third-party sites you reach through external links, or the threat-intelligence and AI providers' own handling of data you choose to send them via our opt-in enrichment features, which are governed by their respective policies."
        },
        {
          "p": "By using the Service you acknowledge this policy. If you do not agree with it, please do not use the Service. Using the analyzer requires a free account; even so, your captures are analyzed entirely in your browser and are never uploaded to us."
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
          "p": "We collect only the limited categories below, and several are optional. None of them include capture contents as described in Section 2."
        },
        {
          "p": "3.1 Account information. A free account is required to use the analyzer. When you register, we collect, via our authentication provider, your email address and a password (your password is handled by the authentication provider; PacketPilot does not store your plaintext password). Optionally, you may add a display name (\"full name\") and an avatar image; the avatar is stored in Supabase Storage. We also store your plan (free or pro), account role, and account status to operate the Service. [Founder/counsel: sign-in is provided via Auth0 (with Supabase as the application database/storage); confirm this account-data description and the sub-processor list in Section 6 reflect that.]"
        },
        {
          "p": "3.2 Billing metadata (paid plans only). Payments are processed entirely by Stripe. We never see or store your card number or other payment details. From Stripe we retain only billing metadata needed to manage your subscription: a Stripe customer id, a Stripe subscription id, the price/plan identifier, the subscription status, the billing amount and currency, the current period end (renewal) date, and whether the subscription is set to cancel at period end."
        },
        {
          "p": "3.3 First-party page-view analytics. We record privacy-preserving page views to understand product usage. For each view we store: an allowlisted canonical route token only (for example \"/\", \"/app#flows\", \"/admin#dashboard\"), a random per-session id (generated in your browser, not tied to your identity unless you are logged in), and — if you are logged in — your user id. Our analytics record may also include a referrer, a coarse country, and the browser user-agent string. Critically, the path is matched against a fixed allowlist and any off-list path is dropped, so a recorded path can never carry an IP address, hostname, SNI, file hash, or query string. We use no third-party advertising or tracking pixels and no cross-site tracking."
        },
        {
          "p": "3.4 Opt-in enrichment data (logged-in users who explicitly consent only). The enrichment features (reputation lookups and the AI Analyst) are OFF by default and require both an account and an explicit opt-in/consent action. When you turn them on for a given analysis, your browser sends to our own server-side functions only: a DERIVED SUMMARY (aggregate statistics and finding metadata — not raw packets) and a small number of PUBLIC IP addresses and PUBLIC domains (such as TLS SNI hostnames). Private/internal IPs, payloads, and the raw capture are never sent. Our functions forward these to the configured providers (see Section 6) to fetch reputation and AI analysis, then return the results to your browser."
        },
        {
          "p": "3.5 Operational and security logs. We keep a limited administrative audit log of privileged actions taken in the admin console, and standard infrastructure/operational logs from our hosting providers. These do not contain capture contents."
        }
      ]
    },
    {
      "heading": "4. How we use information",
      "blocks": [
        {
          "bullets": [
            "To provide and operate the Service, including authenticating you and remembering your preferences.",
            "To create and manage your account, display your name/avatar to you, and let you sign in.",
            "To process subscriptions and payments, manage renewals and cancellations, and prevent billing fraud (via Stripe).",
            "To measure aggregate product usage and improve the Service, using the privacy-preserving page-view analytics described in Section 3.3.",
            "To perform optional, explicitly opted-in enrichment — reputation lookups and AI analysis — on the derived summary and public indicators you choose to submit.",
            "To maintain security, debug issues, and keep an audit trail of administrative actions.",
            "To communicate with you about your account, billing, security, and material changes to the Service."
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
            "Performance of a contract (Art. 6(1)(b)) — operating your account, providing the Service, and processing your subscription.",
            "Legitimate interests (Art. 6(1)(f)) — privacy-preserving first-party analytics, security, fraud prevention, and basic operational logging, balanced against your rights.",
            "Consent (Art. 6(1)(a)) — the optional, opt-in enrichment features (reputation and AI Analyst), which are off by default and which you may decline or stop at any time.",
            "Legal obligation (Art. 6(1)(c)) — retaining certain billing records where required by law."
          ]
        },
        {
          "p": "Subject to applicable law, you have the right to: access the personal data we hold about you; correct inaccurate data; request deletion of your account and associated data; receive an export of your data in a portable form; object to or restrict certain processing; and withdraw consent to enrichment at any time (which does not affect prior processing). You can also minimize the personal data you provide — an account requires only an email address, and your captures are never sent to us regardless."
        },
        {
          "p": "You can delete your account (and trigger deletion of associated profile, subscription-mirror, and analytics linkage data) from within the account settings, or by contacting us at [CONTACT EMAIL e.g. support@...]. We will respond to verified requests within the timeframe required by applicable law. You also have the right to lodge a complaint with your local data protection authority."
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
            "Supabase — authentication, application database, and file storage (avatars). Hosts your account email, password hash, profile, subscription-mirror metadata, and analytics rows.",
            "Stripe — payment processing and subscription management. Handles your card/payment details directly; we receive only the billing metadata in Section 3.2.",
            "Vercel — web hosting and content delivery (CDN) for the site and application."
          ]
        },
        {
          "p": "Used only for opt-in, logged-in enrichment (and only on the derived summary and public indicators you submit):"
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
          "p": "We use only first-party browser storage strictly necessary to run the Service. We do not use third-party tracking cookies or cross-site advertising cookies."
        },
        {
          "bullets": [
            "A session id (a random value in browser storage) used to group your page views for first-party analytics. It is not shared across sites.",
            "An authentication token / session (set when you log in) so you stay signed in. Present only if you have an account and are logged in.",
            "Preferences such as your theme (light/dark) and UI density, stored locally in your browser so the app remembers your choices."
          ]
        },
        {
          "p": "These do not track you across other websites. Capture analysis state lives only in your browser's memory for the duration of the tab and is not persisted to our servers."
        }
      ]
    },
    {
      "heading": "8. Data retention",
      "blocks": [
        {
          "bullets": [
            "Captures and analysis: not retained by us at all — they never leave your browser (Section 2).",
            "Account data: retained for the life of your account; deleted (or anonymized) following a verified deletion request, subject to legal hold requirements.",
            "Billing metadata: retained while your subscription is active and thereafter as required for tax, accounting, and legal compliance ([RETENTION PERIOD, e.g. 7 years — confirm with counsel/your tax jurisdiction]).",
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
          "p": "PacketPilot is operated from [JURISDICTION] and uses cloud sub-processors (Supabase, Stripe, Vercel, and the opt-in enrichment providers) that may store or process data in the United States and other countries. Where personal data is transferred out of the EEA/UK, such transfers are made under appropriate safeguards (for example, the EU Standard Contractual Clauses and/or an adequacy mechanism) as offered by the relevant provider. [Founder/counsel: confirm the specific transfer mechanism for each provider and the regions of your Supabase project.]"
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
          "p": "We may update this policy from time to time. Material changes will be posted here with an updated effective date and, where appropriate, communicated to account holders. Your continued use of the Service after changes take effect constitutes acceptance of the updated policy."
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
      "a": "Only if you are logged in and explicitly opt in to enrichment: a derived summary (aggregate stats and finding metadata, not raw packets) plus a small number of public IP addresses and public domains. These go to our own functions, which proxy them to reputation providers (AbuseIPDB, GreyNoise, VirusTotal) and/or the configured AI provider. Private/internal IPs, payloads, and the raw capture are never sent, and enrichment is off by default."
    },
    {
      "q": "Do I need an account to use PacketPilot?",
      "a": "Yes. A free account is required to use the analyzer (a bundled sample capture can be previewed without one). Creating an account does not change the privacy model: your captures are still analyzed entirely in your browser and are never uploaded to us. An account requires only an email address; Pro billing and opt-in enrichment are additional, optional features."
    },
    {
      "q": "What does the analytics actually record?",
      "a": "First-party page views only: an allowlisted canonical route token (e.g. \"/\" or \"/app#flows\"), a random per-session id, and your user id if logged in (plus referrer, coarse country, and user-agent). Off-allowlist paths are dropped, so a recorded path can never carry an IP, hostname, file hash, or query string. There are no third-party ad or tracking pixels."
    },
    {
      "q": "Does PacketPilot store my credit card?",
      "a": "No. Stripe handles all payment details. PacketPilot stores only billing metadata: Stripe customer and subscription ids, the price/plan, status, amount and currency, renewal date, and the cancel-at-period-end flag."
    },
    {
      "q": "Is this a finished, ready-to-publish policy?",
      "a": "No. It is a template that accurately reflects PacketPilot's data model, but it must be reviewed and adapted by qualified legal counsel, and every [BRACKETED PLACEHOLDER] (entity name, jurisdiction, contact email, effective date, retention periods) must be completed before use."
    }
  ],
  "updated": "July 2, 2026"
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
          "p": "By creating an account, clicking to accept, or otherwise accessing or using the Service, you acknowledge that you have read, understood, and agree to be bound by these Terms and by our Privacy Policy, which is incorporated here by reference. These Terms apply whether you are previewing the sample capture or using the Service as a registered Free or Pro user."
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
            "Optional enrichment. If you are logged in and explicitly opt in, a limited derived summary (aggregate statistics and finding metadata — not raw packets) together with a small number of public IP addresses and public domains (such as TLS SNI hostnames) may be sent to our servers, which proxy them to third-party reputation providers and/or an AI provider to add context. Private and internal IPs, payloads, and the raw capture are never sent. Enrichment is off by default and requires login plus an explicit opt-in action.",
            "A free account is required. Using the analyzer on your own captures requires a free account (a bundled sample capture can be previewed without one). Signing in does not change the client-side privacy model — your captures are never uploaded. Pro adds paid features; opt-in enrichment remains off by default.",
            "Free and Pro tiers. The Service offers a Free tier and a paid Pro subscription, as described under \"Subscriptions, Billing, and Refunds.\""
          ]
        }
      ]
    },
    {
      "heading": "3. Accounts and Eligibility",
      "blocks": [
        {
          "p": "A free account is required to use the analyzer (a bundled sample capture may be previewed without one). To access the analyzer and account-based features (including Pro and opt-in enrichment), you must register an account."
        },
        {
          "bullets": [
            "Eligibility. You must be at least 18 years old (or the age of majority in your jurisdiction) and legally able to enter into these Terms. The Service is not directed to children.",
            "Accurate information. You agree to provide accurate account information (an email address and password; optionally a display name and avatar) and to keep it current.",
            "Account security. You are responsible for safeguarding your credentials and for all activity under your account. Notify us promptly at [CONTACT EMAIL] if you suspect unauthorized use. Authentication and account data are handled through our infrastructure provider as described in \"Third-Party Services.\"",
            "One person per account. You may not share, sell, or transfer your account, and you may not create an account using another person's identity without authorization."
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
            "No abuse of the Service. You must not interfere with, disrupt, overload, or attempt to gain unauthorized access to the Service, its servers, or related systems, or circumvent any access controls, usage limits, or feature gating (including Pro entitlements).",
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
      "heading": "5. Subscriptions, Billing, and Refunds",
      "blocks": [
        {
          "p": "PacketPilot offers a Free tier at no charge and a paid Pro subscription. Pro is available at [PRICE — currently $19 per month or $190 per year], as displayed at checkout. Prices are stated exclusive of any applicable taxes, which may be added."
        },
        {
          "bullets": [
            "Payment processor. All payments are processed by Stripe. We do not collect, store, or have access to your card or payment details — those are handled entirely by Stripe. We store only a Stripe customer ID, subscription ID, status, price, and renewal date associated with your account.",
            "Auto-renewal. Pro subscriptions automatically renew at the end of each billing period (monthly or annual) at the then-current rate, unless you cancel before the renewal date. By subscribing, you authorize recurring charges via Stripe until you cancel.",
            "Cancellation. You may cancel at any time through the billing portal (managed via Stripe) or as otherwise provided in your account. On cancellation, your Pro access continues until the end of the current paid period, after which it does not renew and your account reverts to the Free tier.",
            "Refunds. Except where required by applicable law, fees are non-refundable and we do not provide refunds or credits for partial billing periods or unused time. We may, at our sole discretion, offer a refund or credit in individual cases. [FOUNDER/COUNSEL: confirm or adjust refund stance — e.g., a stated money-back window, or alignment with consumer-protection / right-of-withdrawal rules in [JURISDICTION].]",
            "Price changes. We may change subscription prices or plan features. We will give reasonable advance notice of price changes, which take effect on your next billing cycle; if you do not agree, you may cancel before the change takes effect.",
            "Failed payments. If a payment fails, we may suspend or downgrade Pro access until payment is resolved."
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
          "p": "\"Your Content\" means the packet captures you load and any data derived from them, along with account information such as a display name or avatar you choose to provide."
        },
        {
          "bullets": [
            "You retain your rights. As between you and us, you retain all rights in Your Content. We do not claim ownership of your captures or analysis results.",
            "Captures stay on your device. Because analysis runs client-side, your capture files and their contents are processed locally in your browser and are not uploaded to or stored on our servers. We cannot access your captures.",
            "Limited data you choose to send. The only capture-derived data that may reach our servers is the derived summary and the public IPs and public domains you send via opt-in enrichment, and only when you are logged in and have opted in. You grant us the limited right to process and transmit that data to the relevant third-party providers solely to deliver the enrichment or AI features you requested.",
            "Account profile content. For any display name or avatar you upload, you grant us a limited license to host and display it as needed to operate the Service. You are responsible for ensuring you have the rights to any content you provide."
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
            "Infrastructure. Supabase provides authentication, database, and file storage; Vercel provides web hosting and content delivery (CDN).",
            "Payments. Stripe processes payments and manages the billing portal; your payment details are handled entirely by Stripe.",
            "Opt-in enrichment (reputation). If you opt in, AbuseIPDB, GreyNoise, and VirusTotal may receive the public IPs and public domains we proxy on your behalf to return reputation information.",
            "Opt-in enrichment (AI Analyst). If you opt in, the configured LLM/AI provider may receive the derived summary and public indicators we proxy on your behalf to generate analysis. AI outputs are subject to the disclaimers below.",
            "Analytics. We use first-party, privacy-preserving page-view counts only — an allowlisted set of canonical route tokens, a random per-session ID, and (if you are logged in) your user ID. We do not use third-party ad or tracking pixels or cross-site cookies, and no capture data is included."
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
          "p": "To the maximum extent permitted by applicable law, our total aggregate liability arising out of or relating to these Terms or the Service will not exceed the greater of (a) the total amounts you paid to us for the Service in the twelve (12) months immediately preceding the event giving rise to the claim, or (b) [CURRENCY/AMOUNT — e.g., USD 100]. Some jurisdictions do not allow certain limitations of liability, so some of the above may not apply to you, and nothing in these Terms limits liability that cannot be limited under applicable law."
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
          "p": "You may stop using the Service at any time and may close your account through your account settings or by contacting us. Cancelling a Pro subscription is governed by \"Subscriptions, Billing, and Refunds.\""
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
          "p": "We may modify these Terms from time to time. When we do, we will update the \"Effective date\" and, for material changes, provide reasonable notice (for example, by posting in the Service or by email to registered users). Changes take effect when posted or on the date stated in the notice. Your continued use of the Service after changes take effect constitutes acceptance. If you do not agree to the updated Terms, you must stop using the Service."
        },
        {
          "p": "We may also add, change, suspend, or discontinue features of the Service at any time. We will use reasonable efforts to provide notice of material adverse changes to paid features."
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
            "Entire agreement. These Terms, together with the Privacy Policy and any terms presented at checkout, are the entire agreement between you and us regarding the Service and supersede prior agreements on that subject.",
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
          "p": "Reviewer note: This document is a template intended for founder and counsel review before publication. Complete all bracketed placeholders ([LEGAL ENTITY NAME], [JURISDICTION / GOVERNING LAW], [CONTACT EMAIL], [EFFECTIVE DATE], [PRICE], [CURRENCY/AMOUNT], and any marked decisions) and have qualified legal counsel review it for your jurisdiction and business before relying on it. It is not legal advice."
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
      "a": "Yes. A free account is required to use the analyzer (a bundled sample capture can be previewed without one). Signing in does not change the privacy model: your captures are analyzed entirely in your browser and are never uploaded. An account requires only an email address; Pro and opt-in enrichment are additional, optional features."
    },
    {
      "q": "What is opt-in enrichment, and what data does it send?",
      "a": "If you are logged in and explicitly opt in, a derived summary (aggregate statistics and finding metadata — not raw packets) plus a small number of public IPs and public domains may be sent to our servers, which proxy them to reputation providers (AbuseIPDB, GreyNoise, VirusTotal) and/or an AI provider. Private/internal IPs, payloads, and the raw capture are never sent. It is off by default."
    },
    {
      "q": "How much does Pro cost and how is it billed?",
      "a": "Pro is [currently $19/month or $190/year], billed through Stripe and auto-renewing each period. You can cancel anytime via the billing portal; access continues until the end of the paid period. We never see or store your card details — only a Stripe customer/subscription ID, status, price, and renewal date."
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
  "updated": "July 2, 2026"
};

export const LEGAL_PAGES: Record<"/security" | "/privacy" | "/terms", LegalContent> = {
  "/security": security,
  "/privacy": privacy,
  "/terms": terms,
};
