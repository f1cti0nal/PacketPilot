export interface SeoBlock {
  p?: string;
  bullets?: string[];
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
