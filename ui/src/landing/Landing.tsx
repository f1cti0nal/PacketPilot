import { useEffect, useRef } from "react";
import landingHtml from "./landing.html?raw";
import { trackPageView } from "../lib/analytics/track";

// The marketing landing page is static, self-contained, trusted markup (no user input):
// one scoped `.pp-landing` fragment with its own <style> and inline SVG. Injecting it
// directly avoids a brittle ~1900-line HTML->JSX rewrite and keeps the design byte-for-byte
// what the design panel produced. Every CTA is a plain <a href="/app"> that does a full
// navigation, so no client-side router is needed here.
//
// All interactivity is wired here against the injected DOM via stable data-hooks. Every
// query is guarded so the effect is a harmless no-op when the elements are absent (e.g. the
// unit test mocks the html as "<div>landing</div>"). prefers-reduced-motion is respected:
// tilt and count-up are skipped and final values are shown immediately. Every listener and
// observer is torn down on cleanup.
export function Landing() {
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    trackPageView("/");
  }, []);

  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;

    // Mark JS as active so CSS reveal/no-js gates engage (graceful no-JS degradation
    // relies on these classes being absent when this effect never runs).
    const landing = root.querySelector<HTMLElement>(".pp-landing");
    if (landing) {
      landing.classList.add("pp-js");
      landing.classList.remove("pp-no-js");
    }

    const reduceMotion =
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // Collected teardown callbacks. Each wiring step pushes its own cleanup.
    const cleanups: Array<() => void> = [];

    // ── (1) Mouse-parallax 3D tilt on [data-pp-tilt] ──────────────────────────
    const tilt = root.querySelector<HTMLElement>("[data-pp-tilt]");
    if (tilt && !reduceMotion) {
      const MAX = 6; // degrees
      let raf = 0;
      const onMove = (e: MouseEvent) => {
        const rect = tilt.getBoundingClientRect();
        if (!rect.width || !rect.height) return;
        const px = (e.clientX - rect.left) / rect.width - 0.5;
        const py = (e.clientY - rect.top) / rect.height - 0.5;
        if (raf) cancelAnimationFrame(raf);
        raf = requestAnimationFrame(() => {
          tilt.style.transform =
            `perspective(1600px) rotateX(${(-py * MAX).toFixed(2)}deg) ` +
            `rotateY(${(px * MAX).toFixed(2)}deg)`;
        });
      };
      const onLeave = () => {
        if (raf) cancelAnimationFrame(raf);
        raf = requestAnimationFrame(() => {
          tilt.style.transform = "";
        });
      };
      const host = tilt.closest<HTMLElement>(".pp-mockup-wrap") ?? tilt;
      host.addEventListener("mousemove", onMove);
      host.addEventListener("mouseleave", onLeave);
      cleanups.push(() => {
        if (raf) cancelAnimationFrame(raf);
        host.removeEventListener("mousemove", onMove);
        host.removeEventListener("mouseleave", onLeave);
        tilt.style.transform = "";
      });
    }

    // ── (2) Count-up for every [data-pp-count] when the stats band scrolls in ──
    const counters = Array.from(
      root.querySelectorAll<HTMLElement>("[data-pp-count]"),
    );
    if (counters.length) {
      // Preserve each element's final display text (e.g. "20+") to restore on finish.
      const finals = counters.map((el) => el.textContent ?? "");
      const targets = counters.map((el) => {
        const n = parseInt(el.getAttribute("data-pp-count") ?? "0", 10);
        return Number.isFinite(n) ? n : 0;
      });

      const setFinal = () => {
        counters.forEach((el, i) => {
          el.textContent = finals[i];
        });
      };

      if (reduceMotion || typeof IntersectionObserver !== "function") {
        setFinal();
      } else {
        let started = false;
        const animate = () => {
          if (started) return;
          started = true;
          const DURATION = 1100;
          const start = performance.now();
          let raf = 0;
          const tick = (now: number) => {
            const t = Math.min(1, (now - start) / DURATION);
            const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
            counters.forEach((el, i) => {
              const val = Math.round(targets[i] * eased);
              el.textContent = String(val);
            });
            if (t < 1) {
              raf = requestAnimationFrame(tick);
            } else {
              setFinal();
            }
          };
          raf = requestAnimationFrame(tick);
          cleanups.push(() => {
            if (raf) cancelAnimationFrame(raf);
          });
        };

        const band =
          counters[0].closest(".pp-stats") ??
          counters[0].closest("section") ??
          counters[0];
        const io = new IntersectionObserver(
          (entries) => {
            for (const entry of entries) {
              if (entry.isIntersecting) {
                animate();
                io.disconnect();
                break;
              }
            }
          },
          { threshold: 0.35 },
        );
        io.observe(band);
        cleanups.push(() => io.disconnect());
      }
    }

    // ── (4) Carousel: [data-pp-slide] / prev / next / dots ─────────────────────
    const carousel = root.querySelector<HTMLElement>("[data-pp-carousel]");
    if (carousel) {
      const slides = Array.from(
        carousel.querySelectorAll<HTMLElement>("[data-pp-slide]"),
      );
      const dots = Array.from(
        carousel.querySelectorAll<HTMLElement>("[data-pp-dot]"),
      );
      const prev = carousel.querySelector<HTMLElement>("[data-pp-prev]");
      const next = carousel.querySelector<HTMLElement>("[data-pp-next]");

      if (slides.length) {
        let index = Math.max(
          0,
          slides.findIndex((s) => s.classList.contains("is-active")),
        );
        if (index < 0) index = 0;

        const show = (i: number) => {
          index = (i + slides.length) % slides.length;
          slides.forEach((s, si) =>
            s.classList.toggle("is-active", si === index),
          );
          dots.forEach((d, di) => {
            const active = di === index;
            d.classList.toggle("is-active", active);
            // Pagination dots are buttons in a labelled group (not ARIA tabs, which
            // would require tabpanels) — use aria-current for the active page.
            if (active) d.setAttribute("aria-current", "true");
            else d.removeAttribute("aria-current");
          });
        };

        const handlers: Array<[HTMLElement, string, (e: Event) => void]> = [];
        const bind = (el: HTMLElement | null, fn: () => void) => {
          if (!el) return;
          const onClick = (e: Event) => {
            e.preventDefault();
            fn();
          };
          el.addEventListener("click", onClick);
          handlers.push([el, "click", onClick]);
        };

        bind(prev, () => show(index - 1));
        bind(next, () => show(index + 1));
        dots.forEach((dot, di) => {
          const target = parseInt(dot.getAttribute("data-index") ?? "", 10);
          bind(dot, () => show(Number.isFinite(target) ? target : di));
        });

        show(index);
        cleanups.push(() => {
          handlers.forEach(([el, ev, fn]) => el.removeEventListener(ev, fn));
        });
      }
    }

    // ── (5) Scroll-reveal: add .pp-in to [data-pp-reveal] ──────────────────────
    const reveals = Array.from(
      root.querySelectorAll<HTMLElement>("[data-pp-reveal]"),
    );
    if (reveals.length) {
      if (reduceMotion || typeof IntersectionObserver !== "function") {
        reveals.forEach((el) => el.classList.add("pp-in"));
      } else {
        const io = new IntersectionObserver(
          (entries, obs) => {
            for (const entry of entries) {
              if (entry.isIntersecting) {
                entry.target.classList.add("pp-in");
                obs.unobserve(entry.target);
              }
            }
          },
          { threshold: 0.12, rootMargin: "0px 0px -8% 0px" },
        );
        reveals.forEach((el) => io.observe(el));
        cleanups.push(() => io.disconnect());
      }
    }

    // ── (6) Mobile nav toggle ──────────────────────────────────────────────────
    const navToggle = root.querySelector<HTMLElement>("[data-pp-nav-toggle]");
    const navMenu = root.querySelector<HTMLElement>("[data-pp-nav-menu]");
    if (navToggle && navMenu) {
      const setOpen = (open: boolean) => {
        navMenu.classList.toggle("is-open", open);
        navToggle.setAttribute("aria-expanded", open ? "true" : "false");
      };
      const onToggle = () => {
        const open = navToggle.getAttribute("aria-expanded") === "true";
        setOpen(!open);
      };
      navToggle.addEventListener("click", onToggle);

      // Close the menu after tapping any link inside it.
      const linkHandlers: Array<[HTMLElement, (e: Event) => void]> = [];
      Array.from(navMenu.querySelectorAll<HTMLElement>("a")).forEach((link) => {
        const onLink = () => setOpen(false);
        link.addEventListener("click", onLink);
        linkHandlers.push([link, onLink]);
      });

      setOpen(false);
      cleanups.push(() => {
        navToggle.removeEventListener("click", onToggle);
        linkHandlers.forEach(([el, fn]) => el.removeEventListener("click", fn));
      });
    }

    // ── (7) Workflow tabs: [data-pp-tab] buttons switching [data-pp-panel] ─────
    const tabs = Array.from(root.querySelectorAll<HTMLElement>("[data-pp-tab]"));
    const panels = Array.from(
      root.querySelectorAll<HTMLElement>("[data-pp-panel]"),
    );
    if (tabs.length && panels.length) {
      const select = (id: string, focus: boolean) => {
        tabs.forEach((tab) => {
          const active = tab.getAttribute("data-pp-tab") === id;
          tab.classList.toggle("is-active", active);
          tab.setAttribute("aria-selected", active ? "true" : "false");
          // Roving tabindex: only the active tab is in the tab order.
          tab.setAttribute("tabindex", active ? "0" : "-1");
          if (active && focus) tab.focus();
        });
        panels.forEach((panel) => {
          const active = panel.getAttribute("data-pp-panel") === id;
          panel.classList.toggle("is-active", active);
          panel.hidden = !active;
        });
      };
      const handlers: Array<[HTMLElement, string, (e: Event) => void]> = [];
      tabs.forEach((tab, i) => {
        const id = tab.getAttribute("data-pp-tab") ?? String(i);
        const onClick = () => select(id, false);
        const onKey = (e: Event) => {
          const key = (e as KeyboardEvent).key;
          let to = -1;
          if (key === "ArrowRight" || key === "ArrowDown")
            to = (i + 1) % tabs.length;
          else if (key === "ArrowLeft" || key === "ArrowUp")
            to = (i - 1 + tabs.length) % tabs.length;
          else if (key === "Home") to = 0;
          else if (key === "End") to = tabs.length - 1;
          if (to < 0) return;
          e.preventDefault();
          select(tabs[to].getAttribute("data-pp-tab") ?? String(to), true);
        };
        tab.addEventListener("click", onClick);
        tab.addEventListener("keydown", onKey);
        handlers.push([tab, "click", onClick], [tab, "keydown", onKey]);
      });
      const initial =
        tabs.find((t) => t.classList.contains("is-active")) ?? tabs[0];
      select(initial.getAttribute("data-pp-tab") ?? "0", false);
      cleanups.push(() => {
        handlers.forEach(([el, ev, fn]) => el.removeEventListener(ev, fn));
      });
    }

    return () => {
      cleanups.forEach((fn) => {
        try {
          fn();
        } catch {
          /* best-effort teardown */
        }
      });
      if (landing) landing.classList.remove("pp-js");
    };
  }, []);

  return (
    <div ref={rootRef} dangerouslySetInnerHTML={{ __html: landingHtml }} />
  );
}

export default Landing;
