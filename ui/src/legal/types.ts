/** Structured content for a static legal/trust page, rendered by LegalPage. */
export interface LegalBlock {
  /** A paragraph. Mutually exclusive with `bullets`. */
  p?: string;
  /** A bullet list. */
  bullets?: string[];
}
export interface LegalSection {
  heading: string;
  blocks: LegalBlock[];
}
export interface LegalFaq {
  q: string;
  a: string;
}
export interface LegalContent {
  title: string;
  subtitle?: string;
  /** "Last updated" date, e.g. "June 29, 2026". */
  updated?: string;
  lead: string;
  sections: LegalSection[];
  faq?: LegalFaq[];
}
