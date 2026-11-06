//! Local-only stagenet destination encoder. Reads an address from stdin; never reads wallet keys.
use monero_wallet::address::Network;
use std::io::{Read, Write};
fn encode(text: &str) -> Result<[u8; 96], &'static str> {
    let text = text.trim();
    let bytes = zz_monero::destination::encode(Network::Stagenet, text)?;
    if zz_monero::destination::decode(Network::Stagenet, &bytes)?.to_string() != text {
        return Err("noncanonical destination");
    }
    Ok(bytes)
}
fn main() {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut text = String::new();
        std::io::stdin().take(257).read_to_string(&mut text)?;
        if text.len() > 256 {
            return Err("input too long".into());
        }
        let bytes = encode(&text)?;
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        writeln!(std::io::stdout(), "0x{hex}")?;
        Ok(())
    })();
    if result.is_err() {
        eprintln!("invalid stagenet destination (standard or subaddress required)");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use monero_wallet::{
        address::{AddressType, MoneroAddress, SubaddressIndex},
        ed25519::Scalar,
    };
    use zeroize::Zeroizing;
    #[test]
    fn validates_checksum_network_keys_kind_and_word_layout() {
        let pair = zz_monero::view_pair(&Zeroizing::new(Scalar::ONE)).unwrap();
        for address in [
            pair.legacy_address(Network::Stagenet),
            pair.subaddress(Network::Stagenet, SubaddressIndex::new(0, 1).unwrap()),
        ] {
            let text = address.to_string();
            let bytes = encode(&text).unwrap();
            let raw = monero_base58::decode(&text).unwrap();
            assert_eq!(&bytes[..3], &[1, 2, u8::from(address.is_subaddress())]);
            assert_eq!(&bytes[3..71], &raw[1..]);
            assert!(bytes[71..].iter().all(|b| *b == 0));
            assert_eq!(bytes.chunks_exact(32).count(), 3);
            let mut corrupt = text.into_bytes();
            let last = corrupt.last_mut().unwrap();
            *last = if *last == b'1' { b'2' } else { b'1' };
            assert!(encode(std::str::from_utf8(&corrupt).unwrap()).is_err());
        }
        for network in [Network::Mainnet, Network::Testnet] {
            assert!(encode(&pair.legacy_address(network).to_string()).is_err());
        }
        let standard = pair.legacy_address(Network::Stagenet);
        let integrated = MoneroAddress::new(
            Network::Stagenet,
            AddressType::LegacyIntegrated([0; 8]),
            standard.spend(),
            standard.view(),
        );
        assert!(encode(&integrated.to_string()).is_err());
        assert!(encode("not-an-address").is_err());
    }
}
