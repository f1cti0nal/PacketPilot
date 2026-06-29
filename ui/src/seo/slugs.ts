/** SEO marketing-route slugs. Kept lean (no content) so route.ts can match without pulling
 *  the full page content into the main bundle. A test guards that this matches pages.json. */
export const TOOL_SLUGS = [
  "analyze-pcap-online",
  "wireshark-alternative",
  "pcap-viewer",
  "pcapng-analyzer",
  "pcap-to-csv",
  "extract-files-from-pcap",
] as const;

export type ToolSlug = (typeof TOOL_SLUGS)[number];
export const TOOL_PATHS: ReadonlySet<string> = new Set(TOOL_SLUGS.map((s) => `/${s}`));
