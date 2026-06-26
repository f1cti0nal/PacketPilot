/**
 * Human label for a TCP flags bitmask (RFC 793 + ECN ECE/CWR). Returns "—" when no
 * flags are set. Single source for FlowDetail + PacketInspector — they had drifted
 * copies (the inspector's was missing ECE/CWR). Kept in its own pure module rather than
 * lib/packets.ts because tests mock packets (Tauri carve/extract) and would shadow it.
 */
export function tcpFlagsLabel(flags: number): string {
  if (!flags) return "—";
  const bits: Array<[number, string]> = [
    [0x01, "FIN"],
    [0x02, "SYN"],
    [0x04, "RST"],
    [0x08, "PSH"],
    [0x10, "ACK"],
    [0x20, "URG"],
    [0x40, "ECE"],
    [0x80, "CWR"],
  ];
  return bits.filter(([m]) => (flags & m) !== 0).map(([, n]) => n).join(" ");
}
