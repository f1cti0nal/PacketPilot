import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AdminShell } from "./AdminShell";

vi.mock("./dashboard/AdminDashboard", () => ({ AdminDashboard: () => <div>DASHBOARD_STUB</div> }));
vi.mock("./users/UsersView", () => ({ UsersView: () => <div>USERS_STUB</div> }));
vi.mock("./payments/PaymentsView", () => ({ PaymentsView: () => <div>PAYMENTS_STUB</div> }));
vi.mock("./traffic/TrafficView", () => ({ TrafficView: () => <div>TRAFFIC_STUB</div> }));
vi.mock("./features/FeatureFlagsView", () => ({ FeatureFlagsView: () => <div>FEATURES_STUB</div> }));
vi.mock("./settings/SettingsView", () => ({ SettingsView: () => <div>SETTINGS_STUB</div> }));
vi.mock("./environment/EnvironmentView", () => ({ EnvironmentView: () => <div>ENV_STUB</div> }));

afterEach(() => {
  window.location.hash = "";
});

describe("AdminShell", () => {
  it("renders all seven nav items and defaults to the dashboard", () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    const nav = screen.getByRole("navigation");
    for (const label of ["Dashboard", "Users", "Payments", "Live Traffic", "App Features", "Settings", "Environment"]) {
      expect(within(nav).getByRole("button", { name: label })).toBeInTheDocument();
    }
    expect(screen.getByText("DASHBOARD_STUB")).toBeInTheDocument();
  });

  it("switches content when a nav item is clicked and reflects it in the hash", async () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    await userEvent.click(within(screen.getByRole("navigation")).getByRole("button", { name: "Users" }));
    expect(screen.getByText("USERS_STUB")).toBeInTheDocument();
    expect(window.location.hash).toBe("#users");
  });

  it("signs out from the profile menu", async () => {
    const onSignOut = vi.fn().mockResolvedValue(undefined);
    render(<AdminShell email="a@b.com" onSignOut={onSignOut} />);
    await userEvent.click(screen.getByRole("button", { name: /account menu/i }));
    await userEvent.click(screen.getByRole("button", { name: /sign out/i }));
    expect(onSignOut).toHaveBeenCalled();
  });

  it("routes the Payments section to the payments view", async () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    await userEvent.click(within(screen.getByRole("navigation")).getByRole("button", { name: "Payments" }));
    expect(screen.getByText("PAYMENTS_STUB")).toBeInTheDocument();
    expect(window.location.hash).toBe("#payments");
  });

  it("exposes the theme and density toggles in the top bar", () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    expect(screen.getByRole("button", { name: /switch to (light|dark) theme/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /switch to (comfortable|compact) density/i })).toBeInTheDocument();
  });

  it("routes the Live Traffic section to the traffic view", async () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    await userEvent.click(within(screen.getByRole("navigation")).getByRole("button", { name: "Live Traffic" }));
    expect(screen.getByText("TRAFFIC_STUB")).toBeInTheDocument();
    expect(window.location.hash).toBe("#traffic");
  });

  it("routes the App Features section to the feature flags view", async () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    await userEvent.click(within(screen.getByRole("navigation")).getByRole("button", { name: "App Features" }));
    expect(screen.getByText("FEATURES_STUB")).toBeInTheDocument();
    expect(window.location.hash).toBe("#features");
  });

  it("routes the Settings section to the settings view", async () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    await userEvent.click(within(screen.getByRole("navigation")).getByRole("button", { name: "Settings" }));
    expect(screen.getByText("SETTINGS_STUB")).toBeInTheDocument();
    expect(window.location.hash).toBe("#settings");
  });

  it("routes the Environment section to the environment view", async () => {
    render(<AdminShell email="a@b.com" onSignOut={vi.fn()} />);
    await userEvent.click(within(screen.getByRole("navigation")).getByRole("button", { name: "Environment" }));
    expect(screen.getByText("ENV_STUB")).toBeInTheDocument();
    expect(window.location.hash).toBe("#env");
  });
});
