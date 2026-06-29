import { describe, it, beforeEach } from "vitest";
import { render, fireEvent } from "./render";
import { makeOutput } from "./fixtures";
import { expectNoA11yViolations } from "./axe";

import { ExportMenu } from "../cockpit/ExportMenu";
import { RuleSetsMenu } from "../components/flows/RuleSetsMenu";
import { AiConsent } from "../cockpit/AiConsent";
import { DomainConsent } from "../cockpit/DomainConsent";
import { ReputationConsent } from "../cockpit/ReputationConsent";
import { AiChatPanel } from "../cockpit/AiChatPanel";
import { ThreatRail } from "../cockpit/ThreatRail";
import { ShortcutsOverlay } from "../cockpit/ShortcutsOverlay";
import { EmptyState } from "../components/state/EmptyState";
import { ErrorState } from "../components/state/ErrorState";
import { HomeView } from "../components/home/HomeView";
import type { RecentEntry } from "../types";

const noop = () => {};
const threats = makeOutput().summary.ip_threats ?? [];

const mkRecent = (id: string): RecentEntry => ({
  id,
  name: `${id}.pcap`,
  sizeBytes: 1000,
  analyzedAt: 1_700_000_000_000,
  engineVersion: "0.1.0",
  origin: "wasm",
  summary: makeOutput(),
  flowCount: 1000,
  flowsCached: false,
});

// Automated regression net over the dialog / menu / nav-list accessibility work
// (aria-modal dialogs, role=menu dropdowns with keyboard nav, aria-current lists).
// Runs in the standard Vitest suite, so CI guards these against regressions.
describe("accessibility (axe)", () => {
  beforeEach(() => localStorage.clear());

  it("ExportMenu (open) has no violations", async () => {
    const { container, getByRole } = render(
      <ExportMenu actions={[{ id: "html", label: "HTML report", run: noop }]} />,
    );
    fireEvent.click(getByRole("button", { name: /export/i }));
    await expectNoA11yViolations(container);
  });

  it("RuleSetsMenu (open) has no violations", async () => {
    const { container, getByRole } = render(
      <RuleSetsMenu onLoadFile={noop} onApply={noop} disabled={false} />,
    );
    fireEvent.click(getByRole("button", { name: /rules/i }));
    await expectNoA11yViolations(container);
  });

  it("AiConsent has no violations", async () => {
    const { container } = render(
      <AiConsent model="claude-opus-4-8" onProceed={noop} onCancel={noop} />,
    );
    await expectNoA11yViolations(container);
  });

  it("DomainConsent has no violations", async () => {
    const { container } = render(<DomainConsent domainCount={3} onProceed={noop} onCancel={noop} />);
    await expectNoA11yViolations(container);
  });

  it("ReputationConsent has no violations", async () => {
    const { container } = render(
      <ReputationConsent ipCount={2} providers={["AbuseIPDB", "GreyNoise"]} onProceed={noop} onCancel={noop} />,
    );
    await expectNoA11yViolations(container);
  });

  it("AiChatPanel has no violations", async () => {
    const { container } = render(<AiChatPanel open onClose={noop} output={makeOutput()} model="claude-opus-4-8" />);
    await expectNoA11yViolations(container);
  });

  it("ThreatRail has no violations", async () => {
    const { container } = render(
      <ThreatRail threats={threats} collapsed={false} activeIp={threats[0]?.ip ?? null} onSelect={noop} />,
    );
    await expectNoA11yViolations(container);
  });

  it("ShortcutsOverlay has no violations", async () => {
    const { container } = render(
      <ShortcutsOverlay
        open
        onClose={noop}
        tabs={[{ id: "dashboard", label: "Dashboard" }, { id: "flows", label: "Flows" }]}
      />,
    );
    await expectNoA11yViolations(container);
  });

  it("EmptyState (with CTA) has no violations", async () => {
    const { container } = render(<EmptyState title="No capture loaded" onLoad={noop} />);
    await expectNoA11yViolations(container);
  });

  it("ErrorState (with retry) has no violations", async () => {
    const { container } = render(<ErrorState message="Failed to load" onRetry={noop} />);
    await expectNoA11yViolations(container);
  });

  it("HomeView (first run) has no violations", async () => {
    const { container } = render(
      <HomeView recent={[]} onOpen={noop} onLoadNew={noop} onLoadSample={noop} sampleAvailable />,
    );
    await expectNoA11yViolations(container);
  });

  it("HomeView (returning-user overview) has no violations", async () => {
    const { container } = render(
      <HomeView
        recent={[mkRecent("a"), mkRecent("b")]}
        onOpen={noop}
        onLoadNew={noop}
        onCompare={noop}
      />,
    );
    await expectNoA11yViolations(container);
  });
});
