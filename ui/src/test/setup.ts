import "@testing-library/jest-dom/vitest";
import { afterEach, vi } from "vitest";
import { cleanup } from "@testing-library/react";

afterEach(() => cleanup());

// App auto-collapse reads matchMedia.
if (!window.matchMedia) {
  window.matchMedia = (query: string) =>
    ({ matches: false, media: query, onchange: null,
       addEventListener: () => {}, removeEventListener: () => {},
       addListener: () => {}, removeListener: () => {}, dispatchEvent: () => false }) as MediaQueryList;
}

// IntersectionObserver — fully no-op.
class NoopObserver { observe() {} unobserve() {} disconnect() {} }
vi.stubGlobal("IntersectionObserver", NoopObserver);

// ResizeObserver — fires the callback immediately on observe() AND is
// re-triggerable by sizeScrollElement() so TanStack Virtual can pick up
// new dimensions after the element is sized in a test.
type ROEntry = { cb: ResizeObserverCallback; el: Element; self: ResizeObserver };
const _roRegistry: ROEntry[] = [];
(globalThis as Record<string, unknown>).__roRegistry = _roRegistry;

vi.stubGlobal(
  "ResizeObserver",
  class {
    private cb: ResizeObserverCallback;
    constructor(cb: ResizeObserverCallback) { this.cb = cb; }
    observe(el: Element) {
      const entry: ROEntry = { cb: this.cb, el, self: this as unknown as ResizeObserver };
      _roRegistry.push(entry);
      this._fire(el);
    }
    _fire(el: Element) {
      const h = (el as HTMLElement).offsetHeight || (el as HTMLElement).clientHeight || 0;
      const w = (el as HTMLElement).offsetWidth || (el as HTMLElement).clientWidth || 0;
      this.cb(
        [{ borderBoxSize: [{ blockSize: h, inlineSize: w }], target: el } as unknown as ResizeObserverEntry],
        this as unknown as ResizeObserver,
      );
    }
    unobserve(el: Element) {
      const idx = _roRegistry.findIndex((e) => e.el === el && e.self === (this as unknown as ResizeObserver));
      if (idx >= 0) _roRegistry.splice(idx, 1);
    }
    disconnect() {
      for (let i = _roRegistry.length - 1; i >= 0; i--) {
        if (_roRegistry[i].self === (this as unknown as ResizeObserver)) _roRegistry.splice(i, 1);
      }
    }
  },
);

// jsdom lacks these.
if (!Element.prototype.scrollTo) Element.prototype.scrollTo = () => {};
