import { axe } from "jest-axe";

type AxeOptions = Parameters<typeof axe>[1];

// jsdom has no layout/colour engine, and these tests render isolated component
// fragments rather than whole pages — so contrast and landmark/region rules can't
// apply meaningfully. Everything else (ARIA validity, names, roles, labels) runs.
const DEFAULT_OPTIONS: AxeOptions = {
  rules: {
    "color-contrast": { enabled: false },
    region: { enabled: false },
  },
};

/**
 * Run axe-core over a rendered container and throw a readable error listing any
 * violations. A thin wrapper instead of the jest-axe matcher so the matcher's
 * jest-only typings don't need to be grafted onto Vitest's `expect`.
 */
export async function expectNoA11yViolations(
  container: Element,
  options: AxeOptions = DEFAULT_OPTIONS,
): Promise<void> {
  const results = await axe(container, options);
  if (results.violations.length > 0) {
    const detail = results.violations
      .map((v) => `  • [${v.id}] ${v.help} — ${v.nodes.length} node(s)\n    ${v.helpUrl}`)
      .join("\n");
    throw new Error(`Accessibility violations found:\n${detail}`);
  }
}
