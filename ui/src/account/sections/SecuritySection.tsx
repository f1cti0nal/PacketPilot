import { useState, type FormEvent } from "react";
import { changePassword, changeEmail, signOutEverywhere, deleteAccount } from "../api";
import { Card, fieldCls, btnCls, btnGhost } from "./ui";

export function SecuritySection({ email }: { email: string }) {
  return (
    <Card title="Security" desc="Manage how you sign in — and leave.">
      <PasswordForm email={email} />
      <EmailForm />
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

function PasswordForm({ email }: { email: string }) {
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [conf, setConf] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    if (next !== conf) {
      setError("New passwords don't match");
      return;
    }
    setBusy(true);
    setError(null);
    setDone(false);
    const r = await changePassword(email, cur, next);
    setBusy(false);
    if (!r.ok) {
      setError(r.error ?? "Couldn't change password");
      return;
    }
    setDone(true);
    setCur("");
    setNext("");
    setConf("");
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-2">
      <div className="text-sm font-medium text-[var(--color-text)]">Change password</div>
      <input type="password" autoComplete="current-password" placeholder="Current password" value={cur} onChange={(e) => setCur(e.target.value)} className={fieldCls} aria-label="Current password" required />
      <input type="password" autoComplete="new-password" placeholder="New password" value={next} onChange={(e) => setNext(e.target.value)} className={fieldCls} aria-label="New password" required />
      <input type="password" autoComplete="new-password" placeholder="Confirm new password" value={conf} onChange={(e) => setConf(e.target.value)} className={fieldCls} aria-label="Confirm new password" required />
      <div>
        <button type="submit" disabled={busy} className={btnCls}>
          {busy ? "Saving…" : "Update password"}
        </button>
      </div>
      {error && <Err>{error}</Err>}
      {done && <Note>Password updated.</Note>}
    </form>
  );
}

function EmailForm() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sent, setSent] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    setSent(false);
    const r = await changeEmail(email);
    setBusy(false);
    if (!r.ok) {
      setError(r.error ?? "Couldn't change email");
      return;
    }
    setSent(true);
    setEmail("");
  };

  return (
    <form onSubmit={submit} className="flex flex-col gap-2 border-t border-[var(--color-border)] pt-4">
      <div className="text-sm font-medium text-[var(--color-text)]">Change email</div>
      <input type="email" autoComplete="email" placeholder="New email address" value={email} onChange={(e) => setEmail(e.target.value)} className={fieldCls} aria-label="New email address" required />
      <div>
        <button type="submit" disabled={busy} className={btnCls}>
          {busy ? "Sending…" : "Send confirmation"}
        </button>
      </div>
      {error && <Err>{error}</Err>}
      {sent && <Note>Check your new email for a confirmation link.</Note>}
    </form>
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
    window.location.assign("/app");
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
