//! Just enough of X.509 (RFC 5280) to read a CA certificate from the
//! directory: names, expiry, signature algorithm and key size.

use crate::time;

#[derive(Debug, Clone, PartialEq)]
pub struct Cert {
    /// The subject's common name, or the whole name when it has none.
    pub subject: String,
    pub self_signed: bool,
    pub not_after: Option<i64>,
    /// "sha256RSA", "sha1RSA", "ecdsa-with-SHA384"...
    pub signature: String,
    /// "RSA", "ECC" or the algorithm's OID.
    pub key: String,
    pub key_bits: Option<usize>,
}

impl Cert {
    /// SHA-1 or MD5 signatures, which are no longer collision resistant.
    pub fn weak_hash(&self) -> bool {
        let s = self.signature.to_lowercase();
        s.starts_with("sha1") || s.starts_with("md5") || s.ends_with("sha1")
    }
}

/// One DER element: its tag, its content, and the bytes after it.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)? as usize;
    let (len, head) = if first < 0x80 {
        (first, 2)
    } else {
        let n = first & 0x7f;
        if n == 0 || n > 4 {
            return None;
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *b.get(2 + i)? as usize;
        }
        (len, 2 + n)
    };
    let content = b.get(head..head + len)?;
    Some((tag, content, &b[head + len..]))
}

fn oid(b: &[u8]) -> String {
    let mut parts = Vec::new();
    if let Some(&first) = b.first() {
        parts.push((first / 40) as u64);
        parts.push((first % 40) as u64);
    }
    let mut v: u64 = 0;
    for &x in b.iter().skip(1) {
        v = (v << 7) | (x & 0x7f) as u64;
        if x & 0x80 == 0 {
            parts.push(v);
            v = 0;
        }
    }
    parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

fn text(tag: u8, b: &[u8]) -> String {
    match tag {
        // BMPString: UTF-16 big endian.
        0x1e => {
            let units: Vec<u16> = b
                .chunks(2)
                .filter(|c| c.len() == 2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            String::from_utf16_lossy(&units)
        }
        _ => String::from_utf8_lossy(b).into_owned(),
    }
}

/// "CN=Contoso Root CA" from a Name, or its attributes joined when there is
/// no common name.
fn name(b: &[u8]) -> String {
    let mut parts = Vec::new();
    let mut rest = b;
    while let Some((_, set, next)) = tlv(rest) {
        rest = next;
        let mut inner = set;
        while let Some((_, atv, after)) = tlv(inner) {
            inner = after;
            let Some((_, id, value)) = tlv(atv) else {
                continue;
            };
            let Some((tag, v, _)) = tlv(value) else {
                continue;
            };
            let key = match oid(id).as_str() {
                "2.5.4.3" => "CN",
                "2.5.4.10" => "O",
                "2.5.4.11" => "OU",
                "0.9.2342.19200300.100.1.25" => "DC",
                "2.5.4.6" => "C",
                _ => continue,
            };
            parts.push((key, text(tag, v)));
        }
    }
    match parts.iter().find(|(k, _)| *k == "CN") {
        Some((_, cn)) => cn.clone(),
        None => parts
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

fn when(tag: u8, b: &[u8]) -> Option<i64> {
    let s = std::str::from_utf8(b).ok()?;
    let full = match tag {
        0x17 => {
            let yy: i32 = s.get(..2)?.parse().ok()?;
            format!(
                "{}{}",
                if yy < 50 { 2000 + yy } else { 1900 + yy },
                s.get(2..)?
            )
        }
        0x18 => s.to_string(),
        _ => return None,
    };
    let iso = format!(
        "{}-{}-{}T{}:{}:{}Z",
        full.get(..4)?,
        full.get(4..6)?,
        full.get(6..8)?,
        full.get(8..10)?,
        full.get(10..12)?,
        full.get(12..14)?
    );
    time::parse_iso(&iso)
}

fn signature_name(id: &str) -> String {
    match id {
        "1.2.840.113549.1.1.4" => "md5RSA",
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => "sha1RSA",
        "1.2.840.113549.1.1.11" => "sha256RSA",
        "1.2.840.113549.1.1.12" => "sha384RSA",
        "1.2.840.113549.1.1.13" => "sha512RSA",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        other => other,
    }
    .to_string()
}

/// Bits in a big-endian unsigned integer.
fn bits(n: &[u8]) -> usize {
    let n: &[u8] = match n.iter().position(|&x| x != 0) {
        Some(i) => &n[i..],
        None => return 0,
    };
    n.len() * 8 - n[0].leading_zeros() as usize
}

pub fn parse(der: &[u8]) -> Option<Cert> {
    let (_, cert, _) = tlv(der)?;
    let (_, tbs, _) = tlv(cert)?;
    let mut rest = tbs;
    // Optional [0] version.
    if rest.first() == Some(&0xa0) {
        rest = tlv(rest)?.2;
    }
    let (_, _serial, r) = tlv(rest)?;
    let (_, alg, r) = tlv(r)?;
    let (_, issuer, r) = tlv(r)?;
    let (_, validity, r) = tlv(r)?;
    let (_, subject, r) = tlv(r)?;
    let (_, spki, _) = tlv(r)?;

    let (_, sig_oid, _) = tlv(alg)?;
    let (_, _not_before, v) = tlv(validity)?;
    let (tag, not_after, _) = tlv(v)?;
    let (_, key_alg, k) = tlv(spki)?;
    let (_, key_oid, params) = tlv(key_alg)?;
    let (_, key_bits, _) = tlv(k)?;
    let (key, size) = match oid(key_oid).as_str() {
        "1.2.840.113549.1.1.1" => {
            // BIT STRING: unused-bits byte, then SEQUENCE { modulus, exponent }.
            let size = key_bits
                .get(1..)
                .and_then(tlv)
                .and_then(|(_, seq, _)| tlv(seq))
                .map(|(_, m, _)| bits(m));
            ("RSA".to_string(), size)
        }
        "1.2.840.10045.2.1" => {
            let curve = tlv(params).map(|(_, c, _)| oid(c));
            let size = match curve.as_deref() {
                Some("1.2.840.10045.3.1.7") => Some(256),
                Some("1.3.132.0.34") => Some(384),
                Some("1.3.132.0.35") => Some(521),
                _ => None,
            };
            ("ECC".to_string(), size)
        }
        other => (other.to_string(), None),
    };
    Some(Cert {
        subject: name(subject),
        self_signed: issuer == subject,
        not_after: when(tag, not_after),
        signature: signature_name(&oid(sig_oid)),
        key,
        key_bits: size,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else {
            out.extend([0x82, (content.len() >> 8) as u8, content.len() as u8]);
        }
        out.extend_from_slice(content);
        out
    }

    fn cat(parts: &[Vec<u8>]) -> Vec<u8> {
        parts.concat()
    }

    fn cn(name: &str) -> Vec<u8> {
        let atv = der(
            0x30,
            &cat(&[der(0x06, &[0x55, 0x04, 0x03]), der(0x0c, name.as_bytes())]),
        );
        der(0x30, &der(0x31, &atv))
    }

    /// A structurally valid certificate with an RSA key of `modulus_bytes`.
    pub(crate) fn certificate(
        subject: &str,
        issuer: &str,
        not_after: &str,
        sha1: bool,
        modulus_bytes: usize,
    ) -> Vec<u8> {
        let sig = if sha1 {
            vec![0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05]
        } else {
            vec![0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]
        };
        let alg = der(0x30, &cat(&[der(0x06, &sig), vec![0x05, 0x00]]));
        let mut modulus = vec![0x00, 0xc0];
        modulus.resize(modulus_bytes + 1, 0x11);
        let rsa = der(
            0x30,
            &cat(&[der(0x02, &modulus), der(0x02, &[0x01, 0x00, 0x01])]),
        );
        let mut bit = vec![0x00];
        bit.extend(rsa);
        let rsa_oid = der(
            0x30,
            &cat(&[
                der(
                    0x06,
                    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01],
                ),
                vec![0x05, 0x00],
            ]),
        );
        let spki = der(0x30, &cat(&[rsa_oid, der(0x03, &bit)]));
        let validity = der(
            0x30,
            &cat(&[der(0x17, b"200101000000Z"), der(0x17, not_after.as_bytes())]),
        );
        let tbs = der(
            0x30,
            &cat(&[
                der(0xa0, &der(0x02, &[0x02])),
                der(0x02, &[0x01]),
                alg.clone(),
                cn(issuer),
                validity,
                cn(subject),
                spki,
            ]),
        );
        der(0x30, &cat(&[tbs, alg, der(0x03, &[0x00, 0x00])]))
    }

    #[test]
    fn reads_a_ca_certificate() {
        let c = parse(&certificate(
            "Contoso Root CA",
            "Contoso Root CA",
            "300101000000Z",
            true,
            256,
        ))
        .unwrap();
        assert_eq!(c.subject, "Contoso Root CA");
        assert!(c.self_signed);
        assert_eq!(c.signature, "sha1RSA");
        assert!(c.weak_hash());
        assert_eq!(c.key, "RSA");
        assert_eq!(c.key_bits, Some(2048));
        assert_eq!(c.not_after, time::parse_iso("2030-01-01T00:00:00Z"));

        let issuing = parse(&certificate(
            "Contoso Issuing CA",
            "Contoso Root CA",
            "270101000000Z",
            false,
            128,
        ))
        .unwrap();
        assert!(!issuing.self_signed);
        assert_eq!(issuing.key_bits, Some(1024));
        assert!(!issuing.weak_hash());
    }
}
