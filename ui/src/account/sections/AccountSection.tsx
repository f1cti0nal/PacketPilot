import { useRef, useState, type ChangeEvent } from "react";
import { User as UserIcon, Pencil } from "lucide-react";
import type { AccountProfile } from "../useAccount";
import { updateName, uploadAvatar, removeAvatar } from "../api";
import { Card, Row, fieldCls, btnCls, btnGhost } from "./ui";

const memberSince = (iso: string) => new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "long" });

export function AccountSection({ profile, onChanged }: { profile: AccountProfile; onChanged: () => void }) {
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(profile.full_name ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const saveName = async () => {
    setBusy(true);
    setError(null);
    const r = await updateName(profile.id, name);
    setBusy(false);
    if (!r.ok) {
      setError(r.error ?? "Couldn't save");
      return;
    }
    setEditing(false);
    onChanged();
  };

  const onPickAvatar = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setBusy(true);
    setError(null);
    const r = await uploadAvatar(profile.id, file);
    setBusy(false);
    if (!r.ok) {
      setError(r.error ?? "Upload failed");
      return;
    }
    onChanged();
  };

  const onRemoveAvatar = async () => {
    setBusy(true);
    setError(null);
    const r = await removeAvatar(profile.id);
    setBusy(false);
    if (!r.ok) {
      setError(r.error ?? "Couldn't remove");
      return;
    }
    onChanged();
  };

  return (
    <Card title="Account" desc="Your identity across PacketPilot.">
      <div className="flex items-center gap-4">
        <div className="flex h-16 w-16 items-center justify-center overflow-hidden rounded-full border border-[var(--color-border)] bg-[var(--color-surface-2)]">
          {profile.avatar_url ? (
            <img src={profile.avatar_url} alt="Your avatar" className="h-full w-full object-cover" />
          ) : (
            <UserIcon size={28} className="text-[var(--color-text-faint)]" aria-hidden />
          )}
        </div>
        <div className="flex flex-col gap-1.5">
          <input
            ref={fileRef}
            type="file"
            accept="image/png,image/jpeg,image/webp"
            onChange={onPickAvatar}
            className="hidden"
            aria-label="Upload avatar"
          />
          <div className="flex gap-2">
            <button type="button" disabled={busy} onClick={() => fileRef.current?.click()} className={btnGhost}>
              Change
            </button>
            {profile.avatar_url && (
              <button type="button" disabled={busy} onClick={() => void onRemoveAvatar()} className={btnGhost}>
                Remove
              </button>
            )}
          </div>
          <span className="t-tag text-[var(--color-text-dim)]">PNG, JPEG or WebP, up to 2 MB.</span>
        </div>
      </div>

      <Row label="Display name" hint="Shown in the app and to admins.">
        {editing ? (
          <span className="flex items-center gap-2">
            <input value={name} onChange={(e) => setName(e.target.value)} className={fieldCls} aria-label="Display name" />
            <button type="button" disabled={busy} onClick={() => void saveName()} className={btnCls}>
              {busy ? "Saving…" : "Save"}
            </button>
            <button
              type="button"
              onClick={() => {
                setEditing(false);
                setName(profile.full_name ?? "");
              }}
              className={btnGhost}
            >
              Cancel
            </button>
          </span>
        ) : (
          <span className="flex items-center gap-2">
            <span className="text-sm text-[var(--color-text)]">{profile.full_name || "—"}</span>
            <button
              type="button"
              aria-label="Edit display name"
              onClick={() => setEditing(true)}
              className="rounded-[var(--r-tile)] p-1 text-[var(--color-text-faint)] hover:text-[var(--color-text)]"
            >
              <Pencil size={14} aria-hidden />
            </button>
          </span>
        )}
      </Row>

      <Row label="Email" hint="Change it in Security below.">
        <span className="text-sm text-[var(--color-text)]">{profile.email}</span>
      </Row>
      <Row label="Role">
        <span className="inline-flex items-center rounded-[var(--r-chip)] border border-[var(--color-border)] bg-[var(--color-surface-2)] px-2 py-0.5 t-tag uppercase text-[var(--color-text-dim)]">
          {profile.role}
        </span>
      </Row>
      <Row label="Member since">
        <span className="text-sm text-[var(--color-text-dim)]">{memberSince(profile.created_at)}</span>
      </Row>
      {error && (
        <p role="alert" className="t-tag text-[var(--color-sev-critical)]">
          {error}
        </p>
      )}
    </Card>
  );
}

export default AccountSection;
