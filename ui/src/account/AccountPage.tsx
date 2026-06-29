import type { SessionState } from "../auth/useSession";
import { LoadingState } from "../components/state/LoadingState";
import { ErrorState } from "../components/state/ErrorState";
import { useAccount } from "./useAccount";
import { AccountSection } from "./sections/AccountSection";
import { SecuritySection } from "./sections/SecuritySection";
import { BillingSection } from "./sections/BillingSection";
import { PreferencesSection } from "./sections/PreferencesSection";

type Authed = Extract<SessionState, { status: "authed" }>;

export function AccountPage({ session }: { session: Authed }) {
  const { state, reload } = useAccount();
  if (state.status === "loading") return <LoadingState label="Loading your account…" />;
  if (state.status === "error") return <ErrorState title="Couldn't load your account" message={state.error} />;
  return (
    <div className="flex flex-col gap-6">
      <AccountSection profile={state.profile} onChanged={reload} />
      <SecuritySection email={state.profile.email} />
      <BillingSection plan={session.profile.plan} subscription={state.subscription} trialEndsAt={session.profile.trialEndsAt} />
      <PreferencesSection />
    </div>
  );
}

export default AccountPage;
