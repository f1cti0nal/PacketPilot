/** Stripe-style cents → a whole-dollar display string, e.g. 5700 → "$57". */
export function money(cents: number): string {
  return "$" + Math.round(cents / 100).toLocaleString("en-US");
}

/** ISO timestamp → calendar date "YYYY-MM-DD". */
export function joinedDate(iso: string): string {
  return iso.slice(0, 10);
}

/** A "YYYY-MM-DD" day key → compact "MM-DD" axis label. */
export function shortDay(iso: string): string {
  return iso.slice(5, 10);
}
