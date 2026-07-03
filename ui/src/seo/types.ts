export interface SeoTable {
  /** Screen-reader caption describing the table. */
  caption?: string;
  /** Header cells. columns[0] labels the row-header column. */
  columns: string[];
  /** One array per row, aligned to `columns`; rows[i][0] is the row header. */
  rows: string[][];
  /** 1-based column index to visually emphasize (e.g. the PacketPilot column). */
  highlight?: number;
}
export interface SeoBlock {
  p?: string;
  bullets?: string[];
  table?: SeoTable;
}
export interface SeoSection {
  heading: string;
  blocks: SeoBlock[];
}
export interface SeoFaq {
  q: string;
  a: string;
}
export interface SeoPage {
  slug: string;
  metaTitle: string;
  metaDescription: string;
  h1: string;
  lead: string;
  sections: SeoSection[];
  faq: SeoFaq[];
}
