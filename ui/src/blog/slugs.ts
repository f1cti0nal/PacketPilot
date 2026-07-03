/** Blog post slugs. Routing keys off the "/blog" prefix (see lib/route.ts), so this
 *  list is only used to guard that posts.json and the registry stay in sync. */
export const BLOG_SLUGS = ["anatomy-of-a-pcap-kill-chain"] as const;

export type BlogSlug = (typeof BLOG_SLUGS)[number];
