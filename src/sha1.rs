const H0: u32 = 0x6745_2301;
const H1: u32 = 0xefcd_ab89;
const H2: u32 = 0x98ba_dcfe;
const H3: u32 = 0x1032_5476;
const H4: u32 = 0xc3d2_e1f0;

#[derive(Clone, Default)]
pub struct Sha1 {
    bytes: Vec<u8>,
}

impl Sha1 {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn update(&mut self, bytes: impl AsRef<[u8]>) {
        self.bytes.extend_from_slice(bytes.as_ref());
    }

    pub fn digest(&self) -> [u8; 20] {
        digest(&self.bytes)
    }

    pub fn hexdigest(&self) -> String {
        hex(&self.digest())
    }
}

pub fn digest(bytes: &[u8]) -> [u8; 20] {
    let mut h0 = H0;
    let mut h1 = H1;
    let mut h2 = H2;
    let mut h3 = H3;
    let mut h4 = H4;

    let bit_len = (bytes.len() as u64) * 8;
    let mut msg = Vec::with_capacity((bytes.len() + 9).div_ceil(64) * 64);
    msg.extend_from_slice(bytes);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let j = i * 4;
            *word = u32::from_be_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = h0;
        let mut b = h1;
        let mut c = h2;
        let mut d = h3;
        let mut e = h4;

        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

pub fn hexdigest(bytes: &[u8]) -> String {
    hex(&digest(bytes))
}

pub fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::hexdigest;

    #[test]
    fn sha1_vectors() {
        assert_eq!(hexdigest(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hexdigest(b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }
}
