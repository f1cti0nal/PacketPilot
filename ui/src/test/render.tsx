export { render, screen, within, waitFor, fireEvent, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
export { userEvent };

/** jsdom returns 0-size rects; TanStack Virtual needs a measured scroll element. */
export function sizeScrollElement(el: HTMLElement, height = 600, scrollHeight = 6000) {
  Object.defineProperty(el, "getBoundingClientRect", {
    configurable: true,
    value: () => ({ width: 1000, height, top: 0, left: 0, right: 1000, bottom: height, x: 0, y: 0, toJSON() {} }),
  });
  Object.defineProperty(el, "clientHeight", { configurable: true, value: height });
  Object.defineProperty(el, "scrollHeight", { configurable: true, value: scrollHeight });
}
