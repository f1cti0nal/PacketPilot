/* tslint:disable */
/* eslint-disable */

/**
 * Analyze a raw capture (`.pcap`/`.pcapng`) held entirely in memory.
 *
 * `bytes` is the capture file; `name` becomes the reported `source_path`. Returns a JSON
 * string `{ summary, flows }` (the caller `JSON.parse`s it), or rejects with the engine
 * error string (e.g. an unknown container magic). The provenance hash is left for the
 * caller to fill in (cheaper via WebCrypto than shipping a second hashing pass into wasm).
 */
export function analyze(bytes: Uint8Array, name: string): string;

/**
 * Apply VirusTotal domain reputation verdicts to a completed analysis. `output_json` is the
 * `AnalysisOutput`; `verdicts_json` is `{ "<host>": [ReputationVerdict, ...], ... }`. Pure +
 * network-free — identical to native callers.
 */
export function apply_domain_reputation(output_json: string, verdicts_json: string): string;

/**
 * Apply reputation verdicts to a completed analysis. `output_json` is the `AnalysisOutput` from
 * `analyze`; `verdicts_json` is `{ "<ip>": [ReputationVerdict, ...], ... }` (snake_case). Returns
 * the updated `AnalysisOutput` as JSON. Pure + network-free — identical scoring to native callers.
 */
export function apply_reputation(output_json: string, verdicts_json: string): string;

/**
 * Parse a ruleset, apply it over the pcap `bytes`, and fold the matches into `output_json`.
 *
 * `output_json` is the `AnalysisOutput` (the `.summary` field from `analyze`). Returns a JSON
 * `{ output, loaded, skipped, matches }` where `output` is the updated `AnalysisOutput` with
 * rule-match findings folded in. Pure + wasm-safe — no C deps, no network.
 */
export function apply_rules(bytes: Uint8Array, rules_text: string, output_json: string): string;

/**
 * Re-read `bytes` (a raw `.pcap`/`.pcapng` file) and carve out frames matching `query_json`
 * (a `CarveQueryDto`). Returns raw pcap bytes (`Uint8Array` on the JS side), or rejects with
 * an error string. The capture bytes never leave the device.
 */
export function carve_pcap(bytes: Uint8Array, query_json: string): Uint8Array;

/**
 * Re-read `bytes` (a raw `.pcap`/`.pcapng` file) and decrypt the TLS 1.3 flow described by
 * `query_json` (a `QueryDto`) using the NSS `SSLKEYLOGFILE` text in `keylog_text`.
 *
 * Returns a JSON string matching `TlsDecryptResult` (`{ supported, session_found, version,
 * cipher, cipher_name, keylog_sessions, truncated, reason, records: [...] }`), where each record
 * carries the base64 inner plaintext. Only `TLS_AES_128_GCM_SHA256` is supported this phase;
 * other suites return `supported: false` with an explaining `reason`. The capture and the
 * key-log both stay on the device — neither leaves the browser.
 */
export function decrypt_tls_flow(bytes: Uint8Array, query_json: string, keylog_text: string): string;

/**
 * Export the analysis findings as CEF (Common Event Format) records.
 */
export function export_cef(output_json: string): string;

/**
 * Export the analysis findings as RFC 4180 CSV. `output_json` is the `AnalysisOutput` from `analyze`.
 */
export function export_csv(output_json: string): string;

/**
 * Export the analysis findings as a MISP event stamped with `generated_unix_secs`.
 */
export function export_misp(output_json: string, generated_unix_secs: bigint): string;

/**
 * Export the analysis findings as Sigma detection rules (multi-document YAML).
 */
export function export_sigma(output_json: string): string;

/**
 * Export the analysis findings as a STIX 2.1 bundle stamped with `generated_unix_secs`.
 */
export function export_stix(output_json: string, generated_unix_secs: bigint): string;

/**
 * Re-read `bytes` (a raw `.pcap`/`.pcapng` file) and return the packets for the
 * single flow described by `query_json`, bounded by `caps_json`.
 *
 * Returns a JSON string matching `FlowPackets` (`{ total, truncated, packets: [...] }`),
 * or rejects with an error string. The capture bytes never leave the device.
 */
export function extract_packets(bytes: Uint8Array, query_json: string, caps_json: string): string;

/**
 * Render the full HTML triage report for `output_json` (browser parity with the desktop `save_report`).
 */
export function render_report(output_json: string, generated_unix_secs: bigint, ai_summary?: string | null): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly analyze: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly apply_domain_reputation: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly apply_reputation: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly apply_rules: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly carve_pcap: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly decrypt_tls_flow: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly export_cef: (a: number, b: number) => [number, number, number, number];
    readonly export_csv: (a: number, b: number) => [number, number, number, number];
    readonly export_misp: (a: number, b: number, c: bigint) => [number, number, number, number];
    readonly export_sigma: (a: number, b: number) => [number, number, number, number];
    readonly export_stix: (a: number, b: number, c: bigint) => [number, number, number, number];
    readonly extract_packets: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly render_report: (a: number, b: number, c: bigint, d: number, e: number) => [number, number, number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
