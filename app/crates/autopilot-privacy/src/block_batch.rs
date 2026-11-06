//! Bound Monero's block downloads without changing chain history or scan height.
//!
//! The v0.18.5.4 GET_BLOCKS_FAST request uses a flat epee portable-storage
//! object. Its optional uint64 max_block_count is zero (daemon default) in
//! wallet-rpc requests. Large default batches can repeatedly time out over Tor.
//! Preserve every other field byte-for-byte and request at most 50 blocks.
//! Protocol: monero-project/monero v0.18.5.4, core_rpc_server_commands_defs.h
//! and contrib/epee/include/storages/portable_storage_{base,to_bin}.h.

const HEADER: &[u8] = &[1, 17, 1, 1, 1, 1, 2, 1, 1];
const LIMIT: u64 = 50;
const FIELD: &[u8] = b"max_block_count";

fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> Option<&'a [u8]> {
    let end = offset.checked_add(length)?;
    let value = bytes.get(*offset..end)?;
    *offset = end;
    Some(value)
}

fn varint(bytes: &[u8], offset: &mut usize) -> Option<usize> {
    let width = 1usize << (bytes.get(*offset)? & 3);
    let mut raw = [0u8; 8];
    raw[..width].copy_from_slice(take(bytes, offset, width)?);
    usize::try_from(u64::from_le_bytes(raw) >> 2).ok()
}

/// Only this request's flat scalar/blob encoding is accepted. No recursive
/// parser, allocations based on untrusted lengths, duplicate keys or trailing
/// bytes. Authentication is checked against the original body before this runs.
pub(crate) fn bounded_request(bytes: &[u8]) -> Option<Vec<u8>> {
    if !bytes.starts_with(HEADER) || bytes.len() > 1024 * 1024 {
        return None;
    }
    let mut offset = HEADER.len();
    let count = varint(bytes, &mut offset)?;
    if count == 0 || count > 32 {
        return None;
    }
    let fields_start = offset;
    let mut seen = std::collections::HashSet::new();
    let mut limit_position = None;
    for _ in 0..count {
        let name_len = take(bytes, &mut offset, 1)?[0] as usize;
        let name = take(bytes, &mut offset, name_len)?;
        if name.is_empty() || !seen.insert(name) {
            return None;
        }
        let kind = take(bytes, &mut offset, 1)?[0];
        let value_start = offset;
        let size = match kind {
            1 | 5 | 9 => 8,
            2 | 6 => 4,
            3 | 7 => 2,
            4 | 8 | 11 => 1,
            10 => varint(bytes, &mut offset)?,
            _ => return None,
        };
        take(bytes, &mut offset, size)?;
        if name == FIELD {
            if kind != 5 {
                return None;
            }
            limit_position = Some(value_start);
        }
    }
    if offset != bytes.len() {
        return None;
    }
    if let Some(position) = limit_position {
        let mut result = bytes.to_vec();
        let previous = u64::from_le_bytes(bytes[position..position + 8].try_into().ok()?);
        let capped = if previous == 0 {
            LIMIT
        } else {
            previous.min(LIMIT)
        };
        result[position..position + 8].copy_from_slice(&capped.to_le_bytes());
        Some(result)
    } else {
        let mut result = HEADER.to_vec();
        // At most 33 fields; portable-storage count fits its one-byte encoding.
        result.push(((count + 1) << 2) as u8);
        result.extend_from_slice(&bytes[fields_start..]);
        result.push(FIELD.len() as u8);
        result.extend_from_slice(FIELD);
        result.push(5); // SERIALIZE_TYPE_UINT64
        result.extend_from_slice(&LIMIT.to_le_bytes());
        Some(result)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    // Portable-storage fixture using the upstream wire format: an empty hash
    // history blob, start_height=1234, prune=true and requested_info=1.
    pub(crate) fn request() -> Vec<u8> {
        hex(concat!(
            "01110101010102010110",
            "09626c6f636b5f6964730a00",
            "0c73746172745f68656967687405d204000000000000",
            "057072756e650b01",
            "0e7265717565737465645f696e666f0801"
        ))
    }

    #[test]
    fn caps_default_batches_without_changing_wallet_scan_parameters() {
        let original = request();
        let capped = bounded_request(&original).unwrap();
        assert_eq!(&capped[..9], HEADER);
        assert_eq!(capped[9], 20); // five fields
        assert_eq!(&capped[10..original.len()], &original[10..]);
        assert_eq!(
            &capped[original.len()..],
            &hex("0f6d61785f626c6f636b5f636f756e74053200000000000000")
        );
        assert_eq!(bounded_request(&capped).unwrap(), capped);
        for (input, expected) in [(0u64, 50u64), (7, 7), (1000, 50), (u64::MAX, 50)] {
            let mut body = capped.clone();
            let end = body.len();
            body[end - 8..].copy_from_slice(&input.to_le_bytes());
            let result = bounded_request(&body).unwrap();
            assert_eq!(&result[..end - 8], &body[..end - 8]);
            assert_eq!(&result[end - 8..], &expected.to_le_bytes());
        }
    }

    #[test]
    fn rejects_truncation_duplicates_wrong_types_and_trailing_data() {
        let valid = bounded_request(&request()).unwrap();
        for end in 0..valid.len() {
            assert!(bounded_request(&valid[..end]).is_none(), "prefix {end}");
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(bounded_request(&trailing).is_none());
        let mut duplicate = valid.clone();
        duplicate[9] = 24;
        duplicate.extend_from_slice(&valid[valid.len() - 25..]);
        assert!(bounded_request(&duplicate).is_none());
        let mut wrong = valid.clone();
        let end = wrong.len();
        wrong[end - 9] = 1;
        assert!(bounded_request(&wrong).is_none());
        let mut nested = request();
        nested[20] = 12;
        assert!(bounded_request(&nested).is_none());
        assert!(bounded_request(b"{}").is_none());
    }
}
