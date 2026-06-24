import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { LocalHostsCard } from "./LocalHostsCard";

describe("LocalHostsCard", () => {
  it("renders IP/MAC rows with a vendor label when the OUI is known", () => {
    render(
      <LocalHostsCard
        hosts={[
          { ip: "10.0.0.5", mac: "00:0c:29:ab:cd:ef" },
          { ip: "10.0.0.6", mac: "de:ad:be:ef:00:01" },
        ]}
      />,
    );
    expect(screen.getByText("Local hosts")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.5")).toBeInTheDocument();
    expect(screen.getByText("00:0c:29:ab:cd:ef")).toBeInTheDocument();
    expect(screen.getByText("VMware")).toBeInTheDocument(); // OUI vendor
  });

  it("renders nothing when no ARP was seen", () => {
    render(<LocalHostsCard hosts={[]} />);
    expect(screen.queryByText("Local hosts")).toBeNull();
  });
});
