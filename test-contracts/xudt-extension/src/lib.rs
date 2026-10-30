//! Test-only xUDT extension requiring a proof and metadata on every output.
#![cfg_attr(target_arch = "riscv64", no_std)]

use ckb_std::{ckb_constants::Source, error::SysError, syscalls};

#[cfg(target_arch = "riscv64")]
ckb_std::default_alloc!(4096, 4096, 64);

const BUFFER_SIZE: usize = 2048;
const PROOF: &[u8] = b"channel-proof";
const METADATA: &[u8] = b"channel-data";

fn le32(data: &[u8]) -> Option<usize> {
    Some(u32::from_le_bytes(data.get(..4)?.try_into().ok()?) as usize)
}

// Read a field from a Molecule table/dynvec without trusting its offsets.
fn field(data: &[u8], index: usize) -> Option<&[u8]> {
    if le32(data)? != data.len() {
        return None;
    }
    let first = le32(data.get(4..)?)?;
    if first < 8 || first % 4 != 0 || first > data.len() || index >= first / 4 - 1 {
        return None;
    }
    let start = le32(data.get(4 * (index + 1)..)?)?;
    let end = if index + 1 == first / 4 - 1 {
        data.len()
    } else {
        le32(data.get(4 * (index + 2)..)?)?
    };
    if start < first || end < start {
        return None;
    }
    data.get(start..end)
}

fn unpack(data: &[u8]) -> Option<&[u8]> {
    let payload = data.get(4..)?;
    (le32(data)? == payload.len()).then_some(payload)
}

fn has_proof(witness: &[u8]) -> bool {
    // WitnessArgs.input_type -> XudtWitness.extension_data[0] -> Bytes.
    let proof = field(witness, 1)
        .and_then(unpack)
        .and_then(|data| field(data, 3))
        .and_then(|data| field(data, 0))
        .and_then(unpack);
    proof == Some(PROOF)
}

fn has_metadata(data: &[u8]) -> bool {
    // Skip the uint128 amount, then read XudtData.data[0].
    let metadata = data
        .get(16..)
        .and_then(|data| field(data, 1))
        .and_then(|data| field(data, 0))
        .and_then(unpack);
    metadata == Some(METADATA)
}

fn validate_transfer() -> i32 {
    let mut buffer = [0u8; BUFFER_SIZE];
    match syscalls::load_witness(&mut buffer, 0, 0, Source::GroupInput) {
        Ok(size) if size <= buffer.len() && has_proof(&buffer[..size]) => {}
        _ => return 101,
    }
    for index in 0.. {
        match syscalls::load_cell_data(&mut buffer, 0, index, Source::GroupOutput) {
            Err(SysError::IndexOutOfBound) => return 0,
            Ok(size) if size <= buffer.len() && has_metadata(&buffer[..size]) => {}
            _ => return 103,
        }
    }
    unreachable!()
}

/// xUDT dynamically loads this symbol using the RFC 0052 extension ABI.
/// Owner-mode minting initializes the fixture without proofs or metadata.
///
/// # Safety
/// The caller must supply `length` readable bytes at `args` when non-null.
#[no_mangle]
pub unsafe extern "C" fn validate(owner: i32, index: usize, args: *const u8, length: usize) -> i32 {
    if index != 0 || length != 1 || args.is_null() || *args != 42 {
        return 99;
    }
    if owner != 0 {
        return 0;
    }
    validate_transfer()
}

#[cfg(target_arch = "riscv64")]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    syscalls::exit(104)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sequence(fields: &[&[u8]]) -> Vec<u8> {
        let mut offset = 4 * (1 + fields.len());
        let mut data = Vec::new();
        data.extend_from_slice(
            &((offset + fields.iter().map(|f| f.len()).sum::<usize>()) as u32).to_le_bytes(),
        );
        for field in fields {
            data.extend_from_slice(&(offset as u32).to_le_bytes());
            offset += field.len();
        }
        for field in fields {
            data.extend_from_slice(field);
        }
        data
    }

    fn bytes(data: &[u8]) -> Vec<u8> {
        [(data.len() as u32).to_le_bytes().as_slice(), data].concat()
    }

    #[test]
    fn checks_proof_and_metadata() {
        for (proof, accepted) in [(PROOF, true), (b"wrong".as_slice(), false)] {
            let entries = sequence(&[&bytes(proof)]);
            let xudt = sequence(&[&[], &[], &[], &entries]);
            let witness = sequence(&[&[], &bytes(&xudt), &[]]);
            assert_eq!(has_proof(&witness), accepted);
        }
        for (metadata, accepted) in [(METADATA, true), (b"wrong".as_slice(), false)] {
            let entries = sequence(&[&bytes(metadata)]);
            let tail = sequence(&[&bytes(&[]), &entries]);
            let data = [[0u8; 16].as_slice(), &tail].concat();
            assert_eq!(has_metadata(&data), accepted);
        }
    }

    #[test]
    fn rejects_truncated_and_invalid_offsets() {
        let entries = sequence(&[&bytes(PROOF)]);
        let xudt = sequence(&[&[], &[], &[], &entries]);
        let witness = sequence(&[&[], &bytes(&xudt), &[]]);
        for length in 0..witness.len() {
            assert!(!has_proof(&witness[..length]));
        }
        let mut malformed = witness;
        malformed[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!has_proof(&malformed));
        assert!(!has_metadata(&[0; 16]));
    }

    #[test]
    fn validates_arguments_before_owner_bypass() {
        unsafe {
            assert_eq!(validate(1, 0, [42].as_ptr(), 1), 0);
            assert_eq!(validate(1, 1, [42].as_ptr(), 1), 99);
            assert_eq!(validate(1, 0, [41].as_ptr(), 1), 99);
            assert_eq!(validate(1, 0, core::ptr::null(), 1), 99);
        }
    }
}
