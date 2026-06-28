/** Mask a public URL to scheme + a short prefix; never the full host. */
export function maskUrl(v: string | undefined): string {
  if (!v) return "— Missing";
  const m = /^([a-z]+:\/\/)(.*)$/.exec(v);
  if (!m) return v.slice(0, 8) + "…";
  return m[1] + m[2].slice(0, 8) + "…";
}

/** Mask a public key to a short prefix + suffix only. */
export function maskKey(v: string | undefined): string {
  if (!v) return "— Missing";
  if (v.length <= 12) return v.slice(0, 4) + "…";
  return v.slice(0, 6) + "…" + v.slice(-4);
}
