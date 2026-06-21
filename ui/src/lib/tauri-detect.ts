// Single source of truth for Tauri-runtime detection. Zero dependencies (no @tauri-apps
// imports) so any module — including lightweight, jsdom-tested ones — can import it freely.
export function isTauri(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}
