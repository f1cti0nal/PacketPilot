//! L2 (data-link) stripping: Ethernet II + 802.1Q VLAN unwrapping.

use crate::error::PpError;
use crate::model::packet::PacketMeta;
use crate::Result;

/// EtherType for an 802.1Q VLAN tag.
pub(crate) const ETHERTYPE_VLAN: u16 = 0x8100;
/// EtherType for an 802.1ad (QinQ) service VLAN tag.
pub(crate) const ETHERTYPE_QINQ: u16 = 0x88A8;
/// EtherType for IPv4.
pub(crate) const ETHERTYPE_IPV4: u16 = 0x0800;
/// EtherType for IPv6.
pub(crate) const ETHERTYPE_IPV6: u16 = 0x86DD;
/// EtherType for ARP.
pub(crate) const ETHERTYPE_ARP: u16 = 0x0806;

/// Read a big-endian `u16` from `buf` at `off`, returning `None` if out of bounds.
#[inline]
fn be_u16(buf: &[u8], off: usize) -> Option<u16> {
    let hi = *buf.get(off)?;
    let lo = *buf.get(off + 1)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Strip the Ethernet (and any 802.1Q VLAN) header, returning the inner ethertype and the
/// L3 byte slice. Records the VLAN id into `meta.vlan` when present.
///
/// Returns `(ethertype, l3_slice)`.
pub fn strip_l2<'a>(data: &'a [u8], meta: &mut PacketMeta) -> Result<(u16, &'a [u8])> {
    // dst MAC 6 + src MAC 6 + ethertype 2 = 14 bytes minimum.
    if data.len() < 14 {
        return Err(PpError::Truncated {
            needed: 14,
            had: data.len(),
            offset: meta.index,
        });
    }

    // SAFETY of indexing: bounds checked above and via be_u16 below.
    let mut ethertype = be_u16(data, 12).ok_or(PpError::Truncated {
        needed: 14,
        had: data.len(),
        offset: meta.index,
    })?;
    let mut l3_off = 14usize;

    // Unwrap up to two stacked VLAN tags (QinQ). Each tag is a 2-byte TCI + 2-byte
    // inner ethertype, i.e. it shifts the L3 offset by 4 bytes.
    let mut depth = 0u8;
    while (ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ) && depth < 2 {
        // Need TCI (2) + inner ethertype (2) past the current tag position.
        // The tag's TCI sits at l3_off, inner ethertype at l3_off + 2.
        let tci = match be_u16(data, l3_off) {
            Some(v) => v,
            None => {
                return Err(PpError::Truncated {
                    needed: l3_off + 2,
                    had: data.len(),
                    offset: meta.index,
                })
            }
        };
        // Only record the first (outermost / customer) VLAN id.
        if meta.vlan.is_none() {
            meta.vlan = Some(tci & 0x0FFF);
        }
        ethertype = match be_u16(data, l3_off + 2) {
            Some(v) => v,
            None => {
                return Err(PpError::Truncated {
                    needed: l3_off + 4,
                    had: data.len(),
                    offset: meta.index,
                })
            }
        };
        l3_off += 4;
        depth += 1;
    }

    // Return the L3 slice without panicking even if l3_off == data.len() (empty slice ok)
    // or l3_off > data.len() (caplen shorter than headers => Truncated).
    match data.split_at_checked(l3_off) {
        Some((_, l3)) => Ok((ethertype, l3)),
        None => Err(PpError::Truncated {
            needed: l3_off,
            had: data.len(),
            offset: meta.index,
        }),
    }
}
