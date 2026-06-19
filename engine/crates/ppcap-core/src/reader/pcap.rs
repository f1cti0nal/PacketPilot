//! Classic (legacy) libpcap container source.
//!
//! Parses the 24-byte global header (magic, version, snaplen, network/DLT) and a stream
//! of 16-byte record headers (`ts_sec`, `ts_subsec`, `caplen`, `origlen`) each followed
//! by `caplen` bytes. Built on `pcap-parser`'s bounded `LegacyPcapReader` so memory stays
//! capped at the 64 KiB refill buffer.

use pcap_parser::pcap::LegacyPcapReader;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{PcapBlockOwned, PcapError};

use crate::reader::{LinkType, PacketSource, RawFrame, REFILL_CAPACITY};
use crate::{PpError, Result};

/// Internal reader state. `LegacyPcapReader::new` is fallible, but the public `new` below
/// must (per the module contract) return `Self`; we therefore defer construction to the
/// first `next_frame` call and surface any construction error there. In practice the only
/// failure mode is `BufferTooSmall`, which cannot occur with a 64 KiB capacity.
enum State<R: std::io::Read> {
    /// Not yet constructed; holds the raw reader.
    Pending(Option<R>),
    /// Active bounded reader.
    Active(LegacyPcapReader<R>),
    /// Terminal: a fatal error already occurred or the stream is exhausted.
    Done,
}

/// Streaming source for classic pcap. `R` is the (possibly gunzip-wrapped) byte source.
pub struct LegacyPcapSource<R: std::io::Read> {
    state: State<R>,
    /// DLT from the global header's `network` field (set on the first header block). Until
    /// the header is seen this holds the placeholder passed to `new`.
    link_type: LinkType,
    /// True when the magic indicated nanosecond sub-second timestamps.
    ts_is_nanos: bool,
    /// Snap length from the global header, used to reject over-long records (anti-DoS).
    snaplen: u32,
    /// Monotonic frame counter.
    index: u64,
    /// `pcap-parser` uses a circular buffer; the block returned by `next()` is valid only
    /// until the following `consume`/`refill`. We therefore consume the previous block at
    /// the *start* of the next `next_frame` call. This holds the pending offset.
    pending_consume: Option<usize>,
    size_hint: Option<u64>,
}

impl<R: std::io::Read> LegacyPcapSource<R> {
    /// Construct from an already-magic-identified reader plus the parsed header facts.
    ///
    /// The actual `LegacyPcapReader` is built lazily on the first `next_frame` (see
    /// [`State`]); `link_type` is the placeholder from the sniffer and is overwritten with
    /// the real DLT once the global header block is parsed.
    pub fn new(reader: R, link_type: LinkType, ts_is_nanos: bool, size_hint: Option<u64>) -> Self {
        LegacyPcapSource {
            state: State::Pending(Some(reader)),
            link_type,
            ts_is_nanos,
            snaplen: 0,
            index: 0,
            pending_consume: None,
            size_hint,
        }
    }

    /// Eagerly read the 24-byte global header so [`link_type`](Self::link_type),
    /// `snaplen`, and the timestamp resolution are known before the first `next_frame`. The
    /// header block is consumed; record blocks are left untouched. A stream that ends before
    /// any header (empty file) is not an error here — the first `next_frame` returns
    /// `Ok(None)`.
    pub(crate) fn prime(&mut self) -> Result<()> {
        self.ensure_active()?;
        loop {
            enum Step {
                Done,
                Header {
                    offset: usize,
                    link_type: LinkType,
                    snaplen: u32,
                    is_nanos: bool,
                },
            }
            let reader = match &mut self.state {
                State::Active(r) => r,
                State::Done => return Ok(()),
                State::Pending(_) => unreachable!("ensure_active ran above"),
            };
            let step = match reader.next() {
                Ok((offset, PcapBlockOwned::LegacyHeader(hdr))) => Step::Header {
                    offset,
                    link_type: LinkType::from_u32(hdr.network.0 as u32),
                    snaplen: hdr.snaplen,
                    is_nanos: hdr.is_nanosecond_precision(),
                },
                // First non-header block (or none) reached: header already absent/parsed.
                Ok(_) => Step::Done,
                Err(PcapError::Eof) => Step::Done,
                Err(PcapError::Incomplete(_)) => match reader.refill() {
                    Ok(()) => {
                        if reader.reader_exhausted() && reader.data().is_empty() {
                            Step::Done
                        } else {
                            continue;
                        }
                    }
                    Err(PcapError::Eof) => Step::Done,
                    Err(e) => {
                        let msg = format!("legacy header refill: {e:?}");
                        self.state = State::Done;
                        return Err(PpError::PcapNg(msg));
                    }
                },
                Err(e) => {
                    let msg = format!("legacy header parse: {e:?}");
                    self.state = State::Done;
                    return Err(PpError::PcapNg(msg));
                }
            };
            match step {
                Step::Done => return Ok(()),
                Step::Header {
                    offset,
                    link_type,
                    snaplen,
                    is_nanos,
                } => {
                    self.link_type = link_type;
                    self.snaplen = snaplen;
                    self.ts_is_nanos = is_nanos;
                    if let State::Active(reader) = &mut self.state {
                        reader.consume(offset);
                    }
                    return Ok(());
                }
            }
        }
    }

    /// Ensure the bounded reader is constructed. Returns `Err` only on the (practically
    /// impossible) construction failure.
    fn ensure_active(&mut self) -> Result<()> {
        if let State::Pending(slot) = &mut self.state {
            let reader = slot
                .take()
                .expect("Pending state always holds the reader exactly once");
            match LegacyPcapReader::new(REFILL_CAPACITY, reader) {
                Ok(r) => self.state = State::Active(r),
                Err(e) => {
                    self.state = State::Done;
                    return Err(PpError::PcapNg(format!(
                        "failed to initialize legacy pcap reader: {e:?}"
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Combine seconds and sub-second ticks into `i64` nanoseconds since the epoch.
///
/// Saturating arithmetic guarantees no panic on pathological timestamps (a maliciously huge
/// `ts_sec` cannot overflow into a panic under `panic = "abort"`).
fn legacy_ts_ns(ts_sec: u32, ts_sub: u32, is_nanos: bool) -> i64 {
    let secs = (ts_sec as i64).saturating_mul(1_000_000_000);
    let frac = if is_nanos {
        ts_sub as i64
    } else {
        (ts_sub as i64).saturating_mul(1_000)
    };
    secs.saturating_add(frac)
}

impl<R: std::io::Read> PacketSource for LegacyPcapSource<R> {
    fn link_type(&self) -> LinkType {
        self.link_type
    }

    fn next_frame(&mut self) -> Result<Option<RawFrame<'_>>> {
        self.ensure_active()?;

        // Step 1: deferred-consume the block returned by the previous call. Its borrow has
        // since ended (the caller dropped its RawFrame), so it is safe to shift the buffer.
        if let Some(off) = self.pending_consume.take() {
            if let State::Active(reader) = &mut self.state {
                reader.consume(off);
            }
        }

        // Step 2: advance past non-record blocks (the global header) and refill on
        // Incomplete. No borrow created here escapes the loop: each iteration classifies the
        // current block into a `Step` of *copied* scalars (so the `reader` borrow ends with
        // the match), then mutates `self` and consumes outside that borrow. A record block is
        // left un-consumed so step 3 can re-borrow its data slice.
        let record_offset: usize;
        let ts_ns: i64;
        let wire_len: u32;
        let cap_len: u32;
        loop {
            // Classify the next block without letting the `reader` borrow escape the match.
            enum Step {
                Continue,
                Header {
                    offset: usize,
                    link_type: LinkType,
                    snaplen: u32,
                    is_nanos: bool,
                },
                Record {
                    offset: usize,
                    ts_sec: u32,
                    ts_usec: u32,
                    caplen: u32,
                    origlen: u32,
                },
            }

            let reader = match &mut self.state {
                State::Active(r) => r,
                State::Done => return Ok(None),
                State::Pending(_) => unreachable!("ensure_active ran above"),
            };
            let step = match reader.next() {
                Ok((offset, block)) => match block {
                    PcapBlockOwned::LegacyHeader(hdr) => Step::Header {
                        offset,
                        link_type: LinkType::from_u32(hdr.network.0 as u32),
                        snaplen: hdr.snaplen,
                        is_nanos: hdr.is_nanosecond_precision(),
                    },
                    PcapBlockOwned::Legacy(rec) => Step::Record {
                        offset,
                        ts_sec: rec.ts_sec,
                        ts_usec: rec.ts_usec,
                        caplen: rec.caplen,
                        origlen: rec.origlen,
                    },
                    // A pcapng block inside a legacy stream is nonsensical; skip defensively.
                    PcapBlockOwned::NG(_) => {
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
                            // No progress and nothing buffered => clean EOF at a boundary.
                            if reader.reader_exhausted() && reader.data().is_empty() {
                                self.state = State::Done;
                                return Ok(None);
                            }
                            Step::Continue
                        }
                        Err(PcapError::Eof) => {
                            // Mid-record EOF: trailing bytes that cannot form a record.
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
                            let msg = format!("legacy refill: {e:?}");
                            self.state = State::Done;
                            return Err(PpError::PcapNg(msg));
                        }
                    }
                }
                Err(e) => {
                    let msg = format!("legacy parse: {e:?}");
                    self.state = State::Done;
                    return Err(PpError::PcapNg(msg));
                }
            };

            // `reader` borrow has ended; safe to mutate `self` and consume.
            match step {
                Step::Continue => continue,
                Step::Header {
                    offset,
                    link_type,
                    snaplen,
                    is_nanos,
                } => {
                    self.link_type = link_type;
                    self.snaplen = snaplen;
                    self.ts_is_nanos = is_nanos;
                    if let State::Active(reader) = &mut self.state {
                        reader.consume(offset);
                    }
                    continue;
                }
                Step::Record {
                    offset,
                    ts_sec,
                    ts_usec,
                    caplen,
                    origlen,
                } => {
                    // Reject obviously corrupt / hostile records before yielding.
                    if self.snaplen != 0 && caplen > self.snaplen {
                        self.state = State::Done;
                        return Err(PpError::SnapLenExceeded {
                            snaplen: caplen,
                            max: self.snaplen,
                        });
                    }
                    // `pcap-parser` guarantees `data.len() == caplen` for a fully-parsed
                    // Legacy block; record scalars and break, leaving the block un-consumed.
                    record_offset = offset;
                    ts_ns = legacy_ts_ns(ts_sec, ts_usec, self.ts_is_nanos);
                    wire_len = origlen;
                    cap_len = caplen;
                    break;
                }
            }
        }

        // Step 3: re-borrow the same record block (still un-consumed) to hand its data slice
        // to the caller. This is the single borrow that escapes the function; defer its
        // consume to the next call.
        let link_type = self.link_type;
        let index = self.index;
        let reader = match &mut self.state {
            State::Active(r) => r,
            _ => unreachable!("record located above implies an active reader"),
        };
        let data: &[u8] = match reader.next() {
            Ok((_, PcapBlockOwned::Legacy(rec))) => rec.data,
            // The block was present a moment ago and nothing mutated the buffer in between,
            // so re-reading it must succeed identically.
            _ => {
                // Cannot reassign `self.state` here: it is mutably borrowed via `reader` for
                // the escaping `data` slice. This branch is an "impossible" parser-invariant
                // violation that returns a terminal Err, so leaving the state as-is is fine —
                // the pipeline stops on the first Err and never re-enters this reader.
                return Err(PpError::PcapNg(
                    "legacy record vanished on re-read (parser invariant violated)".into(),
                ));
            }
        };
        self.pending_consume = Some(record_offset);
        self.index += 1;

        Ok(Some(RawFrame {
            index,
            ts_ns,
            iface_id: 0,
            wire_len,
            cap_len,
            link_type,
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

    #[test]
    fn ts_microseconds_scaled_to_nanos() {
        // 1 second + 500_000 µs = 1.5 s = 1_500_000_000 ns
        assert_eq!(legacy_ts_ns(1, 500_000, false), 1_500_000_000);
    }

    #[test]
    fn ts_nanoseconds_passed_through() {
        // 2 seconds + 250 ns
        assert_eq!(legacy_ts_ns(2, 250, true), 2_000_000_250);
    }

    #[test]
    fn ts_does_not_panic_on_max_values() {
        // Saturating arithmetic: must not panic even with u32::MAX seconds.
        let _ = legacy_ts_ns(u32::MAX, u32::MAX, false);
        let _ = legacy_ts_ns(u32::MAX, u32::MAX, true);
    }
}
