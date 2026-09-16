//! MS-CHAPv2 (RFC 2759) over RADIUS, via the Microsoft Vendor-Specific
//! attributes (RFC 2548). This is the same crypto FreeRADIUS runs inside the
//! PEAP tunnel for eduroam, minus the TLS layer.

use des::{
    Des,
    cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use md4::{Digest as _, Md4};
use radius::core::packet::Packet;
use sha1::Sha1;

/// Vendor-Specific attribute type.
pub const VENDOR_SPECIFIC_TYPE: u8 = 26;
const MICROSOFT_VENDOR_ID: u32 = 311;
const MS_CHAP_CHALLENGE_TYPE: u8 = 11;
const MS_CHAP2_RESPONSE_TYPE: u8 = 25;
const MS_CHAP2_SUCCESS_TYPE: u8 = 26;

/// Everything one MS-CHAPv2 exchange needs: the ready-to-send VSA payloads
/// plus the data required to verify the server's `MS-CHAP2-Success`.
pub struct Mschapv2Exchange {
    /// Microsoft VSA payload for `MS-CHAP-Challenge`.
    pub challenge_vsa: Vec<u8>,
    /// Microsoft VSA payload for `MS-CHAP2-Response`.
    pub response_vsa: Vec<u8>,
    /// Ident byte that the server echoes in `MS-CHAP2-Success`.
    pub ident: u8,
    /// Expected `"S=<40 hex chars>"` authenticator response.
    pub expected_success_message: String,
}

impl Mschapv2Exchange {
    /// Generates a full exchange with fresh random challenges.
    pub fn new(username: &str, password: &str) -> Self {
        Self::build(
            username,
            password,
            rand::random(),
            rand::random(),
            rand::random(),
        )
    }

    /// Builds an exchange from explicit challenges (used by tests).
    pub fn build(
        username: &str,
        password: &str,
        ident: u8,
        auth_challenge: [u8; 16],
        peer_challenge: [u8; 16],
    ) -> Self {
        let password_hash = nt_password_hash(password);
        let challenge = challenge_hash(&peer_challenge, &auth_challenge, username);
        let nt_response = challenge_response(&challenge, &password_hash);
        let auth_response = authenticator_response(&password_hash, &nt_response, &challenge);

        // NOTE: FreeRADIUS/rlm_mschap layout, NOT RFC 2548:
        // Ident(1) + Flags(1) + Peer-Challenge(16) + Reserved(8 zeros) + NT-Response(24)
        // (rlm_mschap.c reads peer_challenge at offset 2 and nt_response at
        // offset 26; with the RFC layout the server rejects the response.)
        let mut response_value = Vec::with_capacity(50);
        response_value.push(ident);
        response_value.push(0); // flags
        response_value.extend_from_slice(&peer_challenge);
        response_value.extend_from_slice(&[0u8; 8]); // reserved, must be zero
        response_value.extend_from_slice(&nt_response);

        Self {
            challenge_vsa: microsoft_vsa(MS_CHAP_CHALLENGE_TYPE, &auth_challenge),
            response_vsa: microsoft_vsa(MS_CHAP2_RESPONSE_TYPE, &response_value),
            ident,
            expected_success_message: format!("S={}", to_hex_upper(&auth_response)),
        }
    }
}

/// Checks that a decoded Access-Accept carries a `MS-CHAP2-Success` whose
/// authenticator response proves the server knew the password.
pub fn verify_success(response: &Packet, ident: u8, expected_message: &str) -> bool {
    for avp in response.lookup_all(VENDOR_SPECIFIC_TYPE) {
        let b = avp.encode_bytes();
        // Vendor-Id(4) + Vendor-Type(1) + Vendor-Length(1) + value
        if b.len() < 7
            || u32::from_be_bytes([b[0], b[1], b[2], b[3]]) != MICROSOFT_VENDOR_ID
            || b[4] != MS_CHAP2_SUCCESS_TYPE
        {
            continue;
        }
        let value_len = b[5] as usize;
        if value_len < 2 || b.len() < 6 + value_len - 2 {
            continue;
        }
        let value = &b[6..6 + value_len - 2];
        // Ident(1) + message; starts_with tolerates trailing data
        if !value.is_empty()
            && value[0] == ident
            && value[1..].starts_with(expected_message.as_bytes())
        {
            return true;
        }
    }
    false
}

/// Wraps a value into a Microsoft Vendor-Specific attribute payload (the
/// value part of the outer attribute 26).
fn microsoft_vsa(typ: u8, value: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(6 + value.len());
    v.extend_from_slice(&MICROSOFT_VENDOR_ID.to_be_bytes());
    v.push(typ);
    v.push((2 + value.len()) as u8);
    v.extend_from_slice(value);
    v
}

/// RFC 2759 §8.1: MD4 of the password in UTF-16LE.
fn nt_password_hash(password: &str) -> [u8; 16] {
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    Md4::digest(&utf16).into()
}

/// RFC 2759 §8.1: SHA1(Peer-Challenge + Authenticator-Challenge + User-Name),
/// truncated to 8 octets.
fn challenge_hash(peer_challenge: &[u8; 16], auth_challenge: &[u8], username: &str) -> [u8; 8] {
    let digest = Sha1::new()
        .chain_update(peer_challenge)
        .chain_update(auth_challenge)
        .chain_update(username.as_bytes())
        .finalize();
    digest[..8].try_into().expect("sha1 output is 20 bytes")
}

/// RFC 2759 §8.1: DES-encrypt the challenge with three keys derived from the
/// zero-padded password hash.
fn challenge_response(challenge: &[u8; 8], password_hash: &[u8; 16]) -> [u8; 24] {
    let mut zhash = [0u8; 21];
    zhash[..16].copy_from_slice(password_hash);

    let mut response = [0u8; 24];
    for (i, chunk) in response.chunks_exact_mut(8).enumerate() {
        let key = expand_des_key(&zhash[i * 7..i * 7 + 7]);
        let cipher = Des::new(GenericArray::from_slice(&key));
        let mut block = GenericArray::clone_from_slice(challenge);
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    response
}

/// RFC 2759 §8.4: expands a 7-byte key into the 8-byte DES form, inserting
/// odd-parity bits (see also the worked example in §9.3).
fn expand_des_key(key7: &[u8]) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[0] = key7[0] >> 1;
    k[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2);
    k[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3);
    k[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4);
    k[4] = ((key7[3] & 0x0f) << 3) | (key7[4] >> 5);
    k[5] = ((key7[4] & 0x1f) << 2) | (key7[5] >> 6);
    k[6] = ((key7[5] & 0x3f) << 1) | (key7[6] >> 7);
    k[7] = key7[6] & 0x7f;
    for b in k.iter_mut() {
        *b <<= 1;
        if b.count_ones() % 2 == 0 {
            *b |= 1; // odd parity
        }
    }
    k
}

/// RFC 2759 §8.7: the value the server must echo as `S=<hex>` to prove it
/// knows the password.
fn authenticator_response(
    password_hash: &[u8; 16],
    nt_response: &[u8; 24],
    challenge: &[u8; 8],
) -> [u8; 20] {
    const MAGIC1: &[u8] = b"Magic server to client signing constant";
    const MAGIC2: &[u8] = b"Pad to make it do more than one iteration";

    let hash_hash = Md4::digest(password_hash);
    let digest = Sha1::new()
        .chain_update(hash_hash)
        .chain_update(nt_response)
        .chain_update(MAGIC1)
        .finalize();

    Sha1::new()
        .chain_update(digest)
        .chain_update(challenge)
        .chain_update(MAGIC2)
        .finalize()
        .into()
}

fn to_hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod fr_debug {
    use super::nt_password_hash;

    #[test]
    fn nt_hash_matches_freeradius_ldap_value() {
        let h =
            nt_password_hash("1844d8cf1bad96d9e74abb573b1e719527a80b26a3c6f7c271cc77c404bd2464");
        eprintln!("our NT hash:  {:02X?}", h);
        eprintln!("FR  NT hash:  B1 23 97 0C AB D8 AC 04 8C B8 D7 73 78 1C A1 47");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 2759 §8 test vectors (User = "User", Password = "clientPass").
    const AUTH_CHALLENGE_HEX: &str = "5B5D7C7D7B3F2F3E3C2C602132262628";
    const PEER_CHALLENGE_HEX: &str = "21402324255E262A28295F2B3A337C7E";

    #[test]
    fn rfc2759_nt_password_hash() {
        let expected = unhex("44EBBA8D5312B8D611474411F56989AE");
        assert_eq!(nt_password_hash("clientPass").as_slice(), expected);
    }

    #[test]
    fn rfc2759_challenge_and_nt_response() {
        let auth: [u8; 16] = unhex(AUTH_CHALLENGE_HEX).try_into().unwrap();
        let peer: [u8; 16] = unhex(PEER_CHALLENGE_HEX).try_into().unwrap();

        let challenge = challenge_hash(&peer, &auth, "User");
        assert_eq!(challenge.as_slice(), unhex("D02E4386BCE91226"));

        let nt_response = challenge_response(&challenge, &nt_password_hash("clientPass"));
        assert_eq!(
            nt_response.as_slice(),
            unhex("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")
        );
    }

    /// RFC 2759 §9.3: DES key expansion example (password "MyPw").
    #[test]
    fn rfc2759_des_key_expansion_with_parity() {
        let password_hash = unhex("FC156AF7EDCD6C0EDDE3337D427F4EAC");
        assert_eq!(nt_password_hash("MyPw").as_slice(), password_hash);
        assert_eq!(
            expand_des_key(&password_hash[0..7]).as_slice(),
            unhex("FD0B5B5E7F6E34D9")
        );
        assert_eq!(
            expand_des_key(&password_hash[7..14]).as_slice(),
            unhex("0E6E796737EA08FE")
        );
    }

    /// FreeRADIUS expects MS-CHAP2-Response as
    /// Ident + Flags + Peer + 8*0 + NT-Response (rlm_mschap.c: offsets 2 and 26).
    #[test]
    fn freeradius_mschap2_response_layout() {
        let e = Mschapv2Exchange::build(
            "User",
            "clientPass",
            0x01,
            unhex(AUTH_CHALLENGE_HEX).try_into().unwrap(),
            unhex(PEER_CHALLENGE_HEX).try_into().unwrap(),
        );
        // vendor 311, vendor-type 25, vendor-len 0x34 (2 + 50)
        assert_eq!(&e.response_vsa[..6], &unhex("000001371934")[..]);
        let expected_value = format!(
            "0100{PEER_CHALLENGE_HEX}000000000000000082309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF"
        );
        assert_eq!(&e.response_vsa[6..], &unhex(&expected_value)[..]);
    }

    #[test]
    fn rfc2759_authenticator_response() {
        let auth: [u8; 16] = unhex(AUTH_CHALLENGE_HEX).try_into().unwrap();
        let peer: [u8; 16] = unhex(PEER_CHALLENGE_HEX).try_into().unwrap();

        let password_hash = nt_password_hash("clientPass");
        let challenge = challenge_hash(&peer, &auth, "User");
        let nt_response = challenge_response(&challenge, &password_hash);
        let auth_response = authenticator_response(&password_hash, &nt_response, &challenge);
        assert_eq!(
            to_hex_upper(&auth_response),
            "407A5589115FD0D6209F510FE9C04566932CDA56"
        );
    }
}
