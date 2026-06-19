//! pcapng container source.
//!
//! Handles Section Header Blocks (SHB), Interface Description Blocks (IDB, one per
//! interface, each with its own `linktype` and `if_tsresol`), Enhanced Packet Blocks
//! (EPB), and legacy Simple Packet Blocks (SPB). Unknown block types are skipped by their
//! declared total length. Per-interface `tsresol` is used to normalize timestamps to ns.

use pcap_parser::pcapng::{Block, PcapNGReader};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{PcapBlockOwned, PcapError};

use crate::reader::{LinkType, PacketSource, RawFrame, REFILL_CAPACITY};
use crate::{PpError, Result};

/// One nanosecond expressed in resolution units (the canonical 1e9 ticks/second).
const NANOS_PER_SEC: u128 = 1_000_000_000;

/// Hard cap on the number of interface (IDB) entries retained from a single section. A
/// hostile pcapng can pack a huge run of back-to-back IDBs to grow the interface table with
/// the file size, violating the bounded-heap contract; we refuse to register more than this.
/// 65_536 is far above any legitimate capture while keeping the table negligibly small.
const MAX_INTERFACES: usize = 65_536;

/// Per-interface metadata captured from each IDB, indexed by interface id.
#[derive(Debug, Clone, Copy)]
struct IfaceMeta {
    link_type: LinkType,
    /// Timestamp resolution in *units per second* (e.g. 1_000_000 for µs, 1e9 for ns,
    /// 1<<n for a power-of-two `if_tsresol`). Never zero.
    ts_resolution: u64,
    /// Timestamp offset in whole seconds (`if_tsoffset`).
    ts_offset_secs: i64,
}

impl IfaceMeta {
    /// Convert a raw 64-bit tick count into `i64` nanoseconds since the epoch, applying this
    /// interface's resolution and offset. Uses `i128` intermediates and saturates so a
    /// hostile timestamp can never panic (release builds abort on panic).
    fn ticks_to_ns(&self, ticks: u64) -> i64 {
        let res = self.ts_resolution.max(1) as u128;
        let ns_from_ticks = (ticks as u128).saturating_mul(NANOS_PER_SEC) / res;
        let offset_ns = (self.ts_offset_secs as i128).saturating_mul(NANOS_PER_SEC as i128);
        let total = (ns_from_ticks as i128).saturating_add(offset_ns);
        if total > i64::MAX as i128 {
            i64::MAX
        } else if total < i64::MIN as i128 {
            i64::MIN
        } else {
            total as i64
        }
    }
}

/// Internal reader state — see `LegacyPcapSource::State` for the rationale behind deferred
/// construction (the `PcapNGReader::new` constructor is fallible but the public `new` must
/// return `Self`).
enum State<R: std::io::Read> {
    Pending(Option<R>),
    Active(PcapNGReader<R>),
    Done,
}

/// Streaming source for pcapng.
pub struct PcapNgSource<R: std::io::Read> {
    state: State<R>,
    /// Interface table, filled lazily as IDBs arrive; reset on each new Section Header.
    interfaces: Vec<IfaceMeta>,
    /// Interface 0's link type (or the first IDB seen) for the trait's `link_type()`.
    primary_link_type: LinkType,
    index: u64,
    /// Deferred consume offset for the circular buffer (see the legacy source for details).
    pending_consume: Option<usize>,
    size_hint: Option<u64>,
}

impl<R: std::io::Read> PcapNgSource<R> {
    /// Construct from an already-magic-identified reader. The interface table is empty until
    /// the first IDB arrives; the bounded reader is built lazily on the first `next_frame`.
    pub fn new(reader: R, size_hint: Option<u64>) -> Self {
        PcapNgSource {
            state: State::Pending(Some(reader)),
            interfaces: Vec::new(),
            primary_link_type: LinkType::Unsupported(0),
            index: 0,
            pending_consume: None,
            size_hint,
        }
    }

    /// Eagerly read the Section Header and the first Interface Description Block so that
    /// [`link_type`](Self::link_type) reflects interface 0 before the first `next_frame`.
    /// Blocks consumed here (SHB/IDB and any leading non-packet blocks) will not be revisited;
    /// the first packet block is left un-consumed for `next_frame`. EOF / packet-before-IDB is
    /// not an error at prime time.
    pub(crate) fn prime(&mut self) -> Result<()> {
        self.ensure_active()?;
        loop {
            enum Step {
                Skip {
                    offset: usize,
                },
                Idb {
                    offset: usize,
                    link_type: LinkType,
                    ts_resolution: u64,
                    ts_offset_secs: i64,
                },
                Stop,
            }
            let reader = match &mut self.state {
                State::Active(r) => r,
                State::Done => return Ok(()),
                State::Pending(_) => unreachable!("ensure_active ran above"),
            };
            let step = match reader.next() {
                Ok((offset, block)) => match block {
                    PcapBlockOwned::NG(Block::SectionHeader(_)) => Step::Skip { offset },
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        let ts_resolution = idb.ts_resolution().unwrap_or(1_000_000).max(1);
                        Step::Idb {
                            offset,
                            link_type: LinkType::from_u32(idb.linktype.0 as u32),
                            ts_resolution,
                            ts_offset_secs: idb.if_tsoffset,
                        }
                    }
                    // Packet block reached before/without an IDB to prime on: stop and leave
                    // it un-consumed for next_frame to handle.
                    PcapBlockOwned::NG(Block::EnhancedPacket(_))
                    | PcapBlockOwned::NG(Block::SimplePacket(_)) => Step::Stop,
                    // Other metadata blocks: skip and keep priming toward the first IDB.
                    PcapBlockOwned::NG(_)
                    | PcapBlockOwned::Legacy(_)
                    | PcapBlockOwned::LegacyHeader(_) => Step::Skip { offset },
                },
                Err(PcapError::Eof) => Step::Stop,
                Err(PcapError::Incomplete(_)) => match reader.refill() {
                    Ok(()) => {
                        if reader.reader_exhausted() && reader.data().is_empty() {
                            Step::Stop
                        } else {
                            continue;
                        }
                    }
                    Err(PcapError::Eof) => Step::Stop,
                    Err(e) => {
                        let msg = format!("pcapng header refill: {e:?}");
                        self.state = State::Done;
                        return Err(PpError::PcapNg(msg));
                    }
                },
                Err(e) => {
                    let msg = format!("pcapng header parse: {e:?}");
                    self.state = State::Done;
                    return Err(PpError::PcapNg(msg));
                }
            };
            match step {
                Step::Stop => return Ok(()),
                Step::Skip { offset } => {
                    if let State::Active(reader) = &mut self.state {
                        reader.consume(offset);
                    }
                    continue;
                }
                Step::Idb {
                    offset,
                    link_type,
                    ts_resolution,
                    ts_offset_secs,
                } => {
                    self.push_interface(link_type, ts_resolution, ts_offset_secs)?;
                    if let State::Active(reader) = &mut self.state {
                        reader.consume(offset);
                    }
                    // First IDB registered; interface 0 link type is now known.
                    return Ok(());
                }
            }
        }
    }

    fn ensure_active(&mut self) -> Result<()> {
        if let State::Pending(slot) = &mut self.state {
            let reader = slot
                .take()
                .expect("Pending state always holds the reader exactly once");
            match PcapNGReader::new(REFILL_CAPACITY, reader) {
                Ok(r) => self.state = State::Active(r),
                Err(e) => {
                    self.state = State::Done;
                    return Err(PpError::PcapNg(format!(
                        "failed to initialize pcapng reader: {e:?}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Record an interface from an IDB, deriving its timestamp resolution. Refuses to grow
    /// the interface table past [`MAX_INTERFACES`] so a flood of IDBs cannot make peak heap
    /// scale with the capture size.
    fn push_interface(
        &mut self,
        link_type: LinkType,
        ts_resolution: u64,
        ts_offset_secs: i64,
    ) -> Result<()> {
        if self.interfaces.len() >= MAX_INTERFACES {
            return Err(PpError::PcapNg(format!(
                "interface table exceeded the {MAX_INTERFACES}-entry cap (too many IDBs)"
            )));
        }
        let meta = IfaceMeta {
            link_type,
            ts_resolution,
            ts_offset_secs,
        };
        if self.interfaces.is_empty() {
            self.primary_link_type = link_type;
        }
        self.interfaces.push(meta);
        Ok(())
    }
}

/// What kind of packet block step 2 located, with enough copied scalar state to build the
/// `RawFrame` after re-borrowing the block's data in step 3.
struct LocatedPacket {
    consume_offset: usize,
    ts_ns: i64,
    iface_id: u32,
    wire_len: u32,
    cap_len: u32,
    link_type: LinkType,
    /// `true` for an Enhanced Packet Block, `false` for a Simple Packet Block. Used to
    /// re-borrow the correct variant in step 3.
    is_enhanced: bool,
}

impl<R: std::io::Read> PacketSource for PcapNgSource<R> {
    fn link_type(&self) -> LinkType {
        self.primary_link_type
    }

    fn next_frame(&mut self) -> Result<Option<RawFrame<'_>>> {
        self.ensure_active()?;

        // Step 1: deferred-consume the previous block.
        if let Some(off) = self.pending_consume.take() {
            if let State::Active(reader) = &mut self.state {
                reader.consume(off);
            }
        }

        // Step 2: advance past non-packet blocks (SHB/IDB/NRB/...), updating the interface
        // table, and refill on Incomplete. The located packet block is left un-consumed in
        // the buffer so step 3 can re-borrow its data slice.
        let located: LocatedPacket = loop {
            // Snapshot the interface table needs &self while next() needs &mut self; resolve
            // the borrow by handling everything that needs `self.interfaces` via copies.
            let reader = match &mut self.state {
                State::Active(r) => r,
                State::Done => return Ok(None),
                State::Pending(_) => unreachable!("ensure_active ran above"),
            };

            // Pull the next block; classify without holding the borrow past this match arm.
            // For packet blocks we copy the scalar header fields we need, then break.
            enum Step {
                Continue,
                Shb {
                    offset: usize,
                },
                Idb {
                    offset: usize,
                    link_type: LinkType,
                    ts_resolution: u64,
                    ts_offset_secs: i64,
                },
                Epb {
                    offset: usize,
                    if_id: u32,
                    ticks: u64,
                    caplen: u32,
                    origlen: u32,
                },
                Spb {
                    offset: usize,
                    origlen: u32,
                    caplen: u32,
                },
            }

            let step = match reader.next() {
                Ok((offset, block)) => match block {
                    PcapBlockOwned::NG(Block::SectionHeader(_)) => Step::Shb { offset },
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        let ts_resolution = idb.ts_resolution().unwrap_or(1_000_000).max(1);
                        Step::Idb {
                            offset,
                            link_type: LinkType::from_u32(idb.linktype.0 as u32),
                            ts_resolution,
                            ts_offset_secs: idb.if_tsoffset,
                        }
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        let ticks = ((epb.ts_high as u64) << 32) | (epb.ts_low as u64);
                        Step::Epb {
                            offset,
                            if_id: epb.if_id,
                            ticks,
                            caplen: epb.caplen,
                            origlen: epb.origlen,
                        }
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                        // An SPB carries no caplen of its own; the captured length is the
                        // data slice length (already unpadded by the parser).
                        Step::Spb {
                            offset,
                            origlen: spb.origlen,
                            caplen: spb.data.len() as u32,
                        }
                    }
                    // Every other NG block (NRB, ISB, custom, unknown, ...) is skipped by
                    // the parser's declared length; just consume and continue.
                    PcapBlockOwned::NG(_) => {
                        reader.consume(offset);
                        Step::Continue
                    }
                    // Legacy blocks cannot appear in a pcapng stream; skip defensively.
                    PcapBlockOwned::Legacy(_) | PcapBlockOwned::LegacyHeader(_) => {
                        reader.consume(offset);
                        Step::Continue
                    }
                },
                Err(PcapError::Eof) => {
                    self.state = State::Done;
                    return Ok(None);
                }
                Err(PcapError::Incomplete(_)) => {
                    let pos = reader.position() as u64;
                    match reader.refill() {
                        Ok(()) => {
                            if reader.reader_exhausted() && reader.data().is_empty() {
                                self.state = State::Done;
                                return Ok(None);
                            }
                            Step::Continue
                        }
                        Err(PcapError::Eof) => {
                            let had = reader.data().len();
                            self.state = State::Done;
                            if had == 0 {
                                return Ok(None);
                            }
                            return Err(PpError::Truncated {
                                needed: had + 1,
                                had,
                                offset: pos,
                            });
                        }
                        Err(e) => {
                            // Format before mutating `self.state`: `e` borrows the reader,
                            // which borrows `self.state`.
                            let msg = format!("pcapng refill: {e:?}");
                            self.state = State::Done;
                            return Err(PpError::PcapNg(msg));
                        }
                    }
                }
                Err(e) => {
                    let msg = format!("pcapng parse: {e:?}");
                    self.state = State::Done;
                    return Err(PpError::PcapNg(msg));
                }
            };

            // Apply table mutations / build the located packet outside the `reader` borrow.
            match step {
                Step::Continue => continue,
                Step::Shb { offset } => {
                    // A new section may redefine the interface table from scratch.
                    self.interfaces.clear();
                    self.primary_link_type = LinkType::Unsupported(0);
                    if let State::Active(reader) = &mut self.state {
                        reader.consume(offset);
                    }
                    continue;
                }
                Step::Idb {
                    offset,
                    link_type,
                    ts_resolution,
                    ts_offset_secs,
                } => {
                    self.push_interface(link_type, ts_resolution, ts_offset_secs)?;
                    if let State::Active(reader) = &mut self.state {
                        reader.consume(offset);
                    }
                    continue;
                }
                Step::Epb {
                    offset,
                    if_id,
                    ticks,
                    caplen,
                    origlen,
                } => {
                    let iface = match self.interfaces.get(if_id as usize) {
                        Some(m) => *m,
                        None => {
                            self.state = State::Done;
                            return Err(PpError::PcapNg(format!(
                                "enhanced packet references undefined interface id {if_id}"
                            )));
                        }
                    };
                    break LocatedPacket {
                        consume_offset: offset,
                        ts_ns: iface.ticks_to_ns(ticks),
                        iface_id: if_id,
                        wire_len: origlen,
                        cap_len: caplen,
                        link_type: iface.link_type,
                        is_enhanced: true,
                    };
                }
                Step::Spb {
                    offset,
                    origlen,
                    caplen,
                } => {
                    // SPB always refers to interface 0 (the only one allowed in a section
                    // that uses SPBs). Require that interface to be defined.
                    let iface = match self.interfaces.first() {
                        Some(m) => *m,
                        None => {
                            self.state = State::Done;
                            return Err(PpError::PcapNg(
                                "simple packet block before any interface description".into(),
                            ));
                        }
                    };
                    break LocatedPacket {
                        consume_offset: offset,
                        // SPBs carry no timestamp; use 0 (epoch) deterministically.
                        ts_ns: iface.ticks_to_ns(0),
                        iface_id: 0,
                        wire_len: origlen,
                        cap_len: caplen,
                        link_type: iface.link_type,
                        is_enhanced: false,
                    };
                }
            }
        };

        // Step 3: re-borrow the located packet block to hand out its data slice.
        let index = self.index;
        let reader = match &mut self.state {
            State::Active(r) => r,
            _ => unreachable!("located a packet implies an active reader"),
        };
        let data: &[u8] = match reader.next() {
            Ok((_, PcapBlockOwned::NG(Block::EnhancedPacket(epb)))) if located.is_enhanced => {
                epb.data
            }
            Ok((_, PcapBlockOwned::NG(Block::SimplePacket(spb)))) if !located.is_enhanced => {
                spb.data
            }
            _ => {
                // Cannot reassign `self.state` here: it is mutably borrowed via `reader` for
                // the escaping `data` slice. This branch is an "impossible" parser-invariant
                // violation that returns a terminal Err, so leaving the state as-is is fine —
                // the pipeline stops on the first Err and never re-enters this reader.
                return Err(PpError::PcapNg(
                    "packet block vanished on re-read (parser invariant violated)".into(),
                ));
            }
        };
        self.pending_consume = Some(located.consume_offset);
        self.index += 1;

        Ok(Some(RawFrame {
            index,
            ts_ns: located.ts_ns,
            iface_id: located.iface_id,
            wire_len: located.wire_len,
            cap_len: located.cap_len,
            link_type: located.link_type,
            data,
        }))
    }

    fn size_hint(&self) -> Option<u64> {
        self.size_hint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(res: u64, offset: i64) -> IfaceMeta {
        IfaceMeta {
            link_type: LinkType::Ethernet,
            ts_resolution: res,
            ts_offset_secs: offset,
        }
    }

    #[test]
    fn microsecond_resolution_to_ns() {
        // 1_500_000 µs ticks at 1e6 units/sec = 1.5 s = 1_500_000_000 ns
        let m = iface(1_000_000, 0);
        assert_eq!(m.ticks_to_ns(1_500_000), 1_500_000_000);
    }

    #[test]
    fn nanosecond_resolution_to_ns() {
        // ns resolution: ticks already in ns
        let m = iface(1_000_000_000, 0);
        assert_eq!(m.ticks_to_ns(1_500_000_000), 1_500_000_000);
    }

    #[test]
    fn power_of_two_resolution() {
        // if_tsresol with the high bit set encodes 2^n; ts_resolution() yields 1<<n.
        // Here resolution = 2^16 = 65536 units/sec.
        let m = iface(1 << 16, 0);
        // 65536 ticks == 1 second == 1e9 ns
        assert_eq!(m.ticks_to_ns(65_536), 1_000_000_000);
    }

    #[test]
    fn tsoffset_is_applied() {
        let m = iface(1_000_000, 10);
        // 0 ticks + 10 s offset = 10e9 ns
        assert_eq!(m.ticks_to_ns(0), 10_000_000_000);
    }

    #[test]
    fn no_panic_on_extreme_ticks() {
        let m = iface(1, i64::MAX);
        let _ = m.ticks_to_ns(u64::MAX);
        let m2 = iface(1, i64::MIN);
        let _ = m2.ticks_to_ns(u64::MAX);
    }

    #[test]
    fn zero_resolution_is_safe() {
        // Defensive: a zero resolution must not divide-by-zero.
        let m = iface(0, 0);
        let _ = m.ticks_to_ns(1000);
    }
}
