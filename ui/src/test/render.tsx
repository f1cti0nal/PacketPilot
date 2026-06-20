export { render, screen, within, waitFor, fireEvent, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
export { userEvent };

type ROEntry = { cb: ResizeObserverCallback; el: Element; self: ResizeObserver };

/** jsdom returns 0-size rects; TanStack Virtual needs a measured scroll element.
 *  Sets the element dimensions and re-fires all ResizeObserver callbacks
 *  registered for that element so the virtualizer recalculates its visible rows. */
export function sizeScrollElement(el: HTMLElement, height = 600, scrollHeight = 6000) {
  Object.defineProperty(el, "getBoundingClientRect", {
    configurable: true,
    value: () => ({ width: 1000, height, top: 0, left: 0, right: 1000, bottom: height, x: 0, y: 0, toJSON() {} }),
  });
  Object.defineProperty(el, "clientHeight", { configurable: true, value: height });
  Object.defineProperty(el, "scrollHeight", { configurable: true, value: scrollHeight });
  // TanStack Virtual's getRect() reads offsetHeight/offsetWidth (not clientHeight).
  Object.defineProperty(el, "offsetHeight", { configurable: true, value: height });
  Object.defineProperty(el, "offsetWidth", { configurable: true, value: 1000 });
  // Re-fire any ResizeObserver callbacks registered for this element so the
  // virtualizer picks up the new dimensions and re-renders visible rows.
  const registry: ROEntry[] = (globalThis as Record<string, unknown>).__roRegistry as ROEntry[] ?? [];
  for (const entry of registry) {
    if (entry.el === el) {
      entry.cb(
        [{ borderBoxSize: [{ blockSize: height, inlineSize: 1000 }], target: el } as unknown as ResizeObserverEntry],
        entry.self,
      );
    }
  }
}
