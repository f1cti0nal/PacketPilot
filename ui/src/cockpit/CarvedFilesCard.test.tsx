import { describe, it, expect } from "vitest";
import { render, screen } from "../test/render";
import { CarvedFilesCard } from "./CarvedFilesCard";

describe("CarvedFilesCard", () => {
  it("shows each carved file's hash + a known-bad badge", () => {
    render(
      <CarvedFilesCard
        files={[
          {
            client: "10.0.0.9",
            server: "93.184.216.34",
            sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            size: 68,
            known_bad: true,
          },
          {
            client: "10.0.0.5",
            server: "1.2.3.4",
            sha256: "aaaa021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651ffff",
            size: 4096,
            known_bad: false,
          },
        ]}
      />,
    );
    expect(screen.getByText("Carved files")).toBeInTheDocument();
    expect(screen.getByText(/275a021bbfb6489e54d4/)).toBeInTheDocument();
    expect(screen.getByText("known-bad")).toBeInTheDocument(); // only the known-bad row
    expect(screen.getByText("10.0.0.9")).toBeInTheDocument();
  });

  it("renders nothing when nothing was carved", () => {
    render(<CarvedFilesCard files={[]} />);
    expect(screen.queryByText("Carved files")).toBeNull();
  });
});
