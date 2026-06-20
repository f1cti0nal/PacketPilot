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

// Observers used by virtualization / charts.
class NoopObserver { observe() {} unobserve() {} disconnect() {} }
vi.stubGlobal("ResizeObserver", NoopObserver);
vi.stubGlobal("IntersectionObserver", NoopObserver);

// jsdom lacks these.
if (!Element.prototype.scrollTo) Element.prototype.scrollTo = () => {};
