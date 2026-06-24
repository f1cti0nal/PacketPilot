// MAC OUI (first three bytes) -> device vendor, for labelling L2 hosts. The full IEEE OUI registry
// has tens of thousands of entries; this is a deliberately small, *high-confidence* curated set —
// virtualization stacks, single-board / IoT silicon, and a handful of rock-solid vendor prefixes —
// chosen so a match is reliable. Absence of a match is shown as the bare MAC (never a wrong guess).
const OUI_VENDOR: Record<string, string> = {
  // Virtualization / hypervisors (the highest-value, best-documented prefixes).
  "00:05:69": "VMware",
  "00:0c:29": "VMware",
  "00:1c:14": "VMware",
  "00:50:56": "VMware",
  "00:15:5d": "Microsoft Hyper-V",
  "08:00:27": "VirtualBox",
  "0a:00:27": "VirtualBox",
  "52:54:00": "QEMU / KVM",
  "00:16:3e": "Xen",
  // Single-board computers.
  "b8:27:eb": "Raspberry Pi",
  "dc:a6:32": "Raspberry Pi",
  "e4:5f:01": "Raspberry Pi",
  "28:cd:c1": "Raspberry Pi",
  // Espressif (ESP8266 / ESP32 — ubiquitous IoT silicon).
  "24:0a:c4": "Espressif (ESP)",
  "30:ae:a4": "Espressif (ESP)",
  "5c:cf:7f": "Espressif (ESP)",
  "84:0d:8e": "Espressif (ESP)",
  "a0:20:a6": "Espressif (ESP)",
  "ec:fa:bc": "Espressif (ESP)",
  // Networking gear / well-known vendor prefixes.
  "00:00:0c": "Cisco",
  "00:18:0a": "Cisco Meraki",
  "00:15:6d": "Ubiquiti",
  "dc:9f:db": "Ubiquiti",
  "fc:ec:da": "Ubiquiti",
  "00:09:0f": "Fortinet",
  // Apple (a few high-confidence prefixes).
  "00:03:93": "Apple",
  "28:cf:e9": "Apple",
  "ac:bc:32": "Apple",
  "f0:18:98": "Apple",
};

/** Best-effort device vendor for a `aa:bb:cc:dd:ee:ff` MAC via its OUI, or `null` if unknown. */
export function vendorForMac(mac: string): string | null {
  if (!mac || mac.length < 8) return null;
  return OUI_VENDOR[mac.slice(0, 8).toLowerCase()] ?? null;
}
