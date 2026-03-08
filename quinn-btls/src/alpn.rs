use crate::error::{Error, Result};

#[derive(Clone, Debug)]
pub(crate) struct AlpnProtocol(Vec<u8>);

impl AlpnProtocol {
    #[inline]
    pub(crate) fn encode(&self, encoded: &mut Vec<u8>) {
        encoded.push(self.0.len() as u8);
        encoded.extend_from_slice(&self.0);
    }
}

impl From<Vec<u8>> for AlpnProtocol {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct AlpnProtocols(Vec<AlpnProtocol>);

impl AlpnProtocols {
    pub(crate) const H3: &'static [u8; 2] = b"h3";

    /// Performs the server-side ALPN protocol selection.
    pub(crate) fn select<'a>(&self, offered: &'a [u8]) -> Result<&'a [u8]> {
        for server_proto in &self.0 {
            let mut i = 0;
            while i < offered.len() {
                let len = offered[i] as usize;
                i += 1;

                let client_proto = &offered[i..i + len];
                if server_proto.0 == client_proto {
                    return Ok(client_proto);
                }
                i += len;
            }
        }
        Err(Error::other("ALPN selection failed".into()))
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        for proto in &self.0 {
            proto.encode(&mut out);
        }
        out
    }
}

impl Default for AlpnProtocols {
    fn default() -> Self {
        Self::from(&[Self::H3.to_vec()][..])
    }
}

impl From<&[Vec<u8>]> for AlpnProtocols {
    fn from(protos: &[Vec<u8>]) -> Self {
        let mut out = Vec::with_capacity(protos.len());
        for proto in protos {
            out.push(AlpnProtocol(proto.clone()))
        }
        Self(out)
    }
}

impl From<&Vec<Vec<u8>>> for AlpnProtocols {
    fn from(protos: &Vec<Vec<u8>>) -> Self {
        Self::from(protos.as_slice())
    }
}
