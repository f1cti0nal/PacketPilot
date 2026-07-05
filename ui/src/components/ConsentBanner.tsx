import { useState, type CSSProperties } from "react";
import { gaConfigured, getConsent, grantConsent, denyConsent, type ConsentChoice } from "../lib/analytics/ga";

// Cookie-consent banner for Google Analytics. GA is hard opt-in: nothing loads or is sent to
// Google until the visitor clicks "Accept" (see lib/analytics/ga). Mounted globally in main.tsx
// so it appears on every route. Renders nothing when GA is unconfigured or once a choice exists.
export function ConsentBanner() {
  const [choice, setChoice] = useState<ConsentChoice | null>(() => getConsent());

  if (!gaConfigured || choice !== null) return null;

  const accept = () => {
    grantConsent();
    setChoice("granted");
  };
  const decline = () => {
    denyConsent();
    setChoice("denied");
  };

  return (
    <div role="region" aria-label="Analytics cookie consent" style={banner}>
      <p style={text}>
        We use Google Analytics to understand product usage. It sets cookies only if you accept.
        Your packet captures are never uploaded — this is site analytics only.{" "}
        <a href="/privacy" style={link}>Privacy Policy</a>.
      </p>
      <div style={actions}>
        <button type="button" onClick={decline} style={secondaryBtn}>Decline</button>
        <button type="button" onClick={accept} style={primaryBtn}>Accept</button>
      </div>
    </div>
  );
}

// Flat, theme-aware styling (no shadow — matches the app's flat design language). Uses inline
// styles referencing global CSS variables so it themes correctly on every route, including the
// self-contained landing page.
const banner: CSSProperties = {
  position: "fixed",
  left: "1rem",
  right: "1rem",
  bottom: "1rem",
  zIndex: 2147483000,
  maxWidth: "34rem",
  margin: "0 auto",
  display: "flex",
  flexWrap: "wrap",
  alignItems: "center",
  gap: "0.75rem",
  padding: "0.875rem 1rem",
  background: "var(--color-surface-raised)",
  color: "var(--color-text)",
  border: "1px solid var(--color-border-strong)",
  borderRadius: "0.75rem",
};
const text: CSSProperties = {
  flex: "1 1 16rem",
  margin: 0,
  fontSize: "0.8125rem",
  lineHeight: 1.5,
  color: "var(--color-text-dim)",
};
const link: CSSProperties = { color: "var(--color-accent)", textDecoration: "underline" };
const actions: CSSProperties = { display: "flex", gap: "0.5rem", flex: "0 0 auto" };
const baseBtn: CSSProperties = {
  fontSize: "0.8125rem",
  fontWeight: 500,
  padding: "0.5rem 0.9rem",
  borderRadius: "0.5rem",
  cursor: "pointer",
  border: "1px solid transparent",
  lineHeight: 1,
};
const primaryBtn: CSSProperties = { ...baseBtn, background: "var(--color-accent-deep)", color: "var(--color-on-accent)" };
const secondaryBtn: CSSProperties = {
  ...baseBtn,
  background: "transparent",
  color: "var(--color-text)",
  borderColor: "var(--color-border-strong)",
};

export default ConsentBanner;
