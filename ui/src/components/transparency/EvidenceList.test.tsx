import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";
import { EvidenceList } from "./EvidenceList";

describe("EvidenceList", () => {
  it("renders nothing when empty", () => {
    const { container } = render(<EvidenceList evidence={[]} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("groups items by the prefix before the first colon", () => {
    render(
      <EvidenceList
        evidence={["reputation: abuseipdb malicious 78% (+25)", "c2: periodic beacon 60s"]}
      />,
    );
    expect(screen.getByText("reputation")).toBeInTheDocument();
    expect(screen.getByText("abuseipdb malicious 78% (+25)")).toBeInTheDocument();
    expect(screen.getByText("c2")).toBeInTheDocument();
    expect(screen.getByText("periodic beacon 60s")).toBeInTheDocument();
  });

  it("renders prefix-less strings without a group label", () => {
    render(<EvidenceList evidence={["high fan-out to 40 hosts"]} />);
    expect(screen.getByText("high fan-out to 40 hosts")).toBeInTheDocument();
  });
});
