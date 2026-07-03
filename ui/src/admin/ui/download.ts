// Browser file download for admin exports. Isolated from the pure helpers so the
// DOM/URL side effects stay out of the unit-tested surface.

/** Trigger a client-side download of `text` as `filename`. No-op outside a DOM. */
export function downloadTextFile(filename: string, text: string, mime = "text/csv;charset=utf-8"): void {
  if (typeof document === "undefined" || typeof URL === "undefined" || !URL.createObjectURL) return;
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
