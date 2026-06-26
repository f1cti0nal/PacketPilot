import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { LocalHostsCard } from "./LocalHostsCard";

describe("LocalHostsCard", () => {
  it("renders IP/MAC rows with a vendor label when the OUI is known", () => {
    render(
      <LocalHostsCard
        arp={[
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

  it("merges DHCP hostname/vendor by MAC and shows DHCP-only hosts", () => {
    render(
      <LocalHostsCard
        arp={[{ ip: "10.0.0.5", mac: "00:0c:29:ab:cd:ef" }]}
        dhcp={[
          // Same MAC as the ARP host -> joins, adding the hostname.
          { mac: "00:0c:29:ab:cd:ef", hostname: "DESKTOP-ABC", vendor_class: "MSFT 5.0" },
          // DHCP-only host (no ARP) -> still listed, by MAC, with its vendor-class hint.
          { mac: "02:00:00:00:00:08", hostname: "pixel-7", vendor_class: "android-dhcp-14" },
        ]}
      />,
    );
    expect(screen.getByText("DESKTOP-ABC")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.5")).toBeInTheDocument(); // joined ARP IP
    expect(screen.getByText("pixel-7")).toBeInTheDocument(); // DHCP-only host
    expect(screen.getByText("android-dhcp-14")).toBeInTheDocument(); // vendor-class fallback
  });

  it("renders nothing when neither ARP nor DHCP saw anything", () => {
    render(<LocalHostsCard arp={[]} dhcp={[]} />);
    expect(screen.queryByText("Local hosts")).toBeNull();
  });
});
