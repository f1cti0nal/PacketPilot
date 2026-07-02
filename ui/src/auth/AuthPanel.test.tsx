import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuthPanel } from "./AuthPanel";

const noop = () => {};

describe("AuthPanel", () => {
  it("submits the email + password form", async () => {
    const onSubmit = vi.fn();
    render(<AuthPanel mode="login" busy={false} onSwitchMode={noop} onSubmit={onSubmit} onSocial={noop} />);
    await userEvent.type(screen.getByLabelText(/email/i), "a@b.com");
    await userEvent.type(screen.getByLabelText(/password/i), "hunter2");
    await userEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    expect(onSubmit).toHaveBeenCalledWith("a@b.com", "hunter2");
  });

  it("switches mode via the toggle", async () => {
    const onSwitchMode = vi.fn();
    render(<AuthPanel mode="login" busy={false} onSwitchMode={onSwitchMode} onSubmit={noop} onSocial={noop} />);
    await userEvent.click(screen.getByRole("button", { name: /create an account/i }));
    expect(onSwitchMode).toHaveBeenCalledWith("signup");
  });

  it("calls onSocial for a provider button", async () => {
    const onSocial = vi.fn();
    render(<AuthPanel mode="login" busy={false} onSwitchMode={noop} onSubmit={noop} onSocial={onSocial} />);
    await userEvent.click(screen.getByRole("button", { name: /continue with google/i }));
    expect(onSocial).toHaveBeenCalledWith("google");
  });

  it("shows the confirm-pending state (no form) and resends", async () => {
    const onResend = vi.fn();
    render(
      <AuthPanel
        mode="signup"
        busy={false}
        confirmSentTo="a@b.com"
        onSwitchMode={noop}
        onSubmit={noop}
        onSocial={noop}
        onResend={onResend}
      />,
    );
    expect(screen.getByRole("heading", { name: /check your email/i })).toBeInTheDocument();
    expect(screen.getByText("a@b.com")).toBeInTheDocument();
    expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /resend confirmation/i }));
    expect(onResend).toHaveBeenCalledWith("a@b.com");
  });

  it("renders an error alert", () => {
    render(<AuthPanel mode="login" busy={false} error="Bad creds" onSwitchMode={noop} onSubmit={noop} onSocial={noop} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/bad creds/i);
  });
});
