import { useState } from "react";
import { sendPasswordReset, signOutEverywhere, deleteAccount } from "../api";
import { Card, fieldCls, btnCls, btnGhost } from "./ui";

export function SecuritySection({ email }: { email: string }) {
  return (
    <Card title="Security" desc="Manage how you sign in — and leave.">
      <PasswordReset email={email} />
      <IdentityNote />
      <SignOutAll />
      <DangerZone email={email} />
    </Card>
  );
}

function Note({ children }: { children: string }) {
  return <p className="t-tag text-[var(--color-accent)]">{children}</p>;
}
function Err({ children }: { children: string }) {
  return (
    <p role="alert" className="t-tag text-[var(--color-sev-critical)]">
      {children}
    </p>
  );
}

function PasswordReset({ email }: { email: string }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  const run = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    setSent(false);
    const r = await sendPasswordReset(email);
    setBusy(false);
    if (!r.ok) {
      setError(r.error ?? "Couldn't send reset email");
      return;
    }
    setSent(true);
  };

  return (
    <div className="flex flex-col gap-2">
      <div className="text-sm font-medium text-[var(--color-text)]">Change password</div>
      <p className="t-tag text-[var(--color-text-dim)]">
        We'll email <span className="text-[var(--color-text)]">{email}</span> a secure link to set a new password.
      </p>
      <div>
        <button type="button" disabled={busy} onClick={() => void run()} className={btnCls}>
          {busy ? "Sending…" : "Send password reset email"}
        </button>
      </div>
      {error && <Err>{error}</Err>}
      {sent && <Note>Check your email for the reset link.</Note>}
    </div>
  );
}

function IdentityNote() {
  return (
    <div className="flex flex-col gap-2 border-t border-[var(--color-border)] pt-4">
      <div className="text-sm font-medium text-[var(--color-text)]">Email &amp; connected logins</div>
      <p className="t-tag text-[var(--color-text-dim)]">
        Your email address and social sign-ins (Google, GitHub) are managed by your identity provider. Update them from
        your provider account, then sign in again.
      </p>
    </div>
  );
}

function SignOutAll() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async () => {
    setBusy(true);
    setError(null);
    const r = await signOutEverywhere();
    if (!r.ok) {
      setError(r.error ?? "Couldn't sign out");
      setBusy(false);
      return;
    }
    // Session ended — leave the account area.
    window.location.assign("/");
  };
  return (
    <div className="flex flex-col gap-2 border-t border-[var(--color-border)] pt-4">
      <div className="text-sm font-medium text-[var(--color-text)]">Sign out of all devices</div>
      <div>
        <button type="button" disabled={busy} onClick={() => void run()} className={btnGhost}>
          {busy ? "Signing out…" : "Sign out everywhere"}
        </button>
      </div>
      {error && <Err>{error}</Err>}
    </div>
  );
}

function DangerZone({ email }: { email: string }) {
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const armed = confirm.trim().toLowerCase() === email.toLowerCase();
  const run = async () => {
    if (!armed || busy) return;
    setBusy(true);
    setError(null);
    const r = await deleteAccount();
    if (!r.ok) {
      setError(r.error ?? "Couldn't delete account");
      setBusy(false);
      return;
    }
    window.location.assign("/");
  };
  return (
    <div className="flex flex-col gap-2 rounded-[var(--r-tile)] border border-[color:color-mix(in_srgb,var(--color-sev-critical)_40%,transparent)] p-4">
      <div className="text-sm font-medium text-[var(--color-sev-critical)]">Delete account</div>
      <p className="t-tag text-[var(--color-text-dim)]">
        Permanently deletes your account, profile, and subscription. This can't be undone. Type{" "}
        <span className="text-[var(--color-text)]">{email}</span> to confirm.
      </p>
      <input value={confirm} onChange={(e) => setConfirm(e.target.value)} className={fieldCls} aria-label="Type your email to confirm deletion" placeholder={email} />
      <div>
        <button
          type="button"
          disabled={!armed || busy}
          onClick={() => void run()}
          className="inline-flex items-center justify-center rounded-[var(--r-tile)] bg-[var(--color-sev-critical)] px-3 py-1.5 text-sm font-medium text-[var(--color-on-accent)] disabled:opacity-50"
        >
          {busy ? "Deleting…" : "Delete my account"}
        </button>
      </div>
      {error && <Err>{error}</Err>}
    </div>
  );
}

export default SecuritySection;
