# Encrypted DNS (DoH/DoT) — implementation plan

Spec: [2026-06-24-encrypted-dns-design.md](../specs/2026-06-24-encrypted-dns-design.md)

Engine stats rollup + a dashboard panel. Direct to main. Mirrors the passive-DNS rollup-and-panel
pattern.

## Engine (`engine/crates/ppcap-core/src/`)

1. `model/summary.rs`: `EncryptedDnsHost { host, resolver, flows }`; `Summary.encrypted_dns`
   (serde-default) + `Summary::empty()`; `enrich/reputation.rs` literal.
2. `stats/mod.rs`: `encrypted_dns: HashMap<(IpAddr, String), u64>` (+ `new()`); module consts
   `DOT_PORT` + `DOH_ENDPOINTS`; helpers `is_doh_endpoint` (exact / dot-bounded subdomain),
   `client_endpoint` / `client_endpoint_peer` (role-by-server-port, `None` when ambiguous);
   `bump_encrypted_dns` (bounded). Fold in `observe_scored_flow` (DoH in the SNI block — before the
   `per_domain` entry moves `host`; DoT by `:853`). Build `encrypted_dns` in `finish` (top-64). Test:
   DoH-by-SNI client, DoT-by-port client, non-DoH excluded.

## UI (`ui/src/`)

3. `types.ts`: `EncryptedDnsHost` + `encrypted_dns?` on the summary type.
   `cockpit/EncryptedDnsCard.tsx`: `host → resolver` list, hidden when empty.
   `components/Dashboard.tsx`: import + render (next to DnsResolutions/LocalHosts).
4. Test: `cockpit/EncryptedDnsCard.test.tsx`.

## Verify

Engine: full `cargo test -p ppcap-core` · `clippy`. UI: `test:coverage` · `build`. `build:wasm`
(wasm embeds the engine → rebuild so the field appears in browser analysis). Verify branch = main,
then commit direct to `main`.
