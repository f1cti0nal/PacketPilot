import { ThemeToggle } from "../../cockpit/ThemeToggle";
import { DensityToggle } from "../../cockpit/DensityToggle";
import { Card, Row } from "./ui";

export function PreferencesSection() {
  return (
    <Card title="Preferences" desc="How PacketPilot looks on this device. Saved in your browser.">
      <Row label="Theme" hint="Light or dark appearance.">
        <ThemeToggle />
      </Row>
      <Row label="Density" hint="Comfortable or compact spacing.">
        <DensityToggle />
      </Row>
    </Card>
  );
}

export default PreferencesSection;
