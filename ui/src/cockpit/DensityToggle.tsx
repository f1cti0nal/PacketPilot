import { useCallback, useEffect, useState } from "react";
import { Rows3, Rows2 } from "lucide-react";
import { BTN_GHOST_ICON } from "./primitives";
import {
  resolveDensity,
  applyDensity,
  setDensity,
  DENSITY_EVENT,
  type Density,
} from "../lib/density";

/**
 * The active density plus a toggle, kept in sync across every mounted instance via the
 * `DENSITY_EVENT` window event (and cross-tab `storage` events).
 */
export function useDensity(): readonly [Density, () => void] {
  const [density, setDensityState] = useState<Density>(() => resolveDensity());

  useEffect(() => {
    const sync = () => setDensityState(resolveDensity());
    sync();
    window.addEventListener(DENSITY_EVENT, sync);
    window.addEventListener("storage", sync);
    return () => {
      window.removeEventListener(DENSITY_EVENT, sync);
      window.removeEventListener("storage", sync);
    };
  }, []);

  // Keep <html data-density> truthful even if the pre-paint bootstrap never ran (e.g. tests).
  useEffect(() => {
    applyDensity(density);
  }, [density]);

  const toggle = useCallback(() => {
    setDensity(resolveDensity() === "compact" ? "comfortable" : "compact");
  }, []);

  return [density, toggle] as const;
}

/** Button that flips the dashboard between comfortable and compact spacing. */
export function DensityToggle() {
  const [density, toggle] = useDensity();
  const isCompact = density === "compact";
  return (
    <button
      type="button"
      data-component="DensityToggle"
      onClick={toggle}
      aria-label={isCompact ? "Switch to comfortable density" : "Switch to compact density"}
      aria-pressed={isCompact}
      title={isCompact ? "Comfortable spacing" : "Compact spacing"}
      className={BTN_GHOST_ICON}
    >
      {isCompact ? <Rows2 size={14} aria-hidden /> : <Rows3 size={14} aria-hidden />}
    </button>
  );
}

export default DensityToggle;
