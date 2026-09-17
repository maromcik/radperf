use radius::core::rfc2869::MESSAGE_AUTHENTICATOR_TYPE;

use crate::error::AppError;

const RADIUS_HEADER_LEN: usize = 20;

/// HMAC-MD5 (RFC 2104) on top of the `md5` crate.
fn hmac_md5(key: &[u8], msg: &[u8]) -> [u8; 16] {
    const BLOCK_SIZE: usize = 64;

    let mut key_block = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        key_block[..16].copy_from_slice(&md5::compute(key).0);
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let ipad: Vec<u8> = key_block.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = key_block.iter().map(|b| b ^ 0x5c).collect();

    let inner = md5::compute([ipad, msg.to_vec()].concat());
    md5::compute([opad, inner.to_vec()].concat()).0
}

/// Recomputes the Request Authenticator of an encoded Accounting-Request in
/// place.
///
/// RFC 2866: unlike Access-Request (random), the authenticator is
/// MD5(Code+ID+Length+16 zero octets+Attributes+Secret). The `radius` crate
/// fills it with random bytes, and FreeRADIUS drops packets with an invalid
/// signature, so we fix it after encoding.
pub fn fix_accounting_authenticator(encoded: &mut [u8], secret: &[u8]) -> Result<(), AppError> {
    if encoded.len() < RADIUS_HEADER_LEN {
        return Err(AppError::RadiusPacketError(
            "packet shorter than RADIUS header".to_owned(),
        ));
    }
    let mut ctx = md5::Context::new();
    ctx.consume(&encoded[..4]);
    ctx.consume([0u8; 16]);
    ctx.consume(&encoded[RADIUS_HEADER_LEN..]);
    ctx.consume(secret);
    let digest = ctx.compute();
    encoded[4..RADIUS_HEADER_LEN].copy_from_slice(&digest.0);
    Ok(())
}

/// Recomputes the Message-Authenticator of an encoded Access-Request in place.
///
/// RFC 3579: the value is HMAC-MD5 over the entire packet (with the
/// Message-Authenticator attribute itself set to 16 zero bytes), keyed by the
/// shared secret. This is what radclient does when the input file contains
/// `Message-Authenticator = 0x00`.
pub fn fix_message_authenticator(encoded: &mut [u8], secret: &[u8]) -> Result<(), AppError> {
    let mut off = RADIUS_HEADER_LEN;
    while off + 2 <= encoded.len() {
        let typ = encoded[off];
        let len = encoded[off + 1] as usize;
        if len < 2 || off + len > encoded.len() {
            return Err(AppError::RadiusPacketError(
                "malformed attribute list".to_owned(),
            ));
        }
        if typ == MESSAGE_AUTHENTICATOR_TYPE {
            if len != 18 {
                return Err(AppError::RadiusPacketError(format!(
                    "Message-Authenticator attribute must be 16 bytes long, got {}",
                    len - 2
                )));
            }
            let digest = hmac_md5(secret, encoded);
            encoded[off + 2..off + len].copy_from_slice(&digest);
            return Ok(());
        }
        off += len;
    }
    Err(AppError::RadiusPacketError(
        "Message-Authenticator attribute not found".to_owned(),
    ))
}
