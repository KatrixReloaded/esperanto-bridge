//! The three big-endian euint256 words specified in contracts/INTERFACES.md.
use monero_wallet::{
    address::{AddressType, MoneroAddress, Network},
    ed25519::CompressedPoint,
};

fn network_code(network: Network) -> u8 {
    match network {
        Network::Mainnet => 0,
        Network::Testnet => 1,
        Network::Stagenet => 2,
    }
}

pub fn encode(network: Network, address: &str) -> Result<[u8; 96], &'static str> {
    let address = crate::validate_destination(network, address)?;
    let mut bytes = [0; 96];
    bytes[0] = 1;
    bytes[1] = network_code(network);
    bytes[2] = u8::from(address.is_subaddress());
    let raw = monero_base58::decode(&address.to_string()).ok_or("invalid base58 address")?;
    if raw.len() != 69 {
        return Err("unsupported address size");
    }
    bytes[3..71].copy_from_slice(&raw[1..]);
    Ok(bytes)
}

pub fn decode(network: Network, bytes: &[u8; 96]) -> Result<MoneroAddress, &'static str> {
    if bytes[0] != 1
        || bytes[1] != network_code(network)
        || bytes[2] > 1
        || bytes[71..].iter().any(|b| *b != 0)
    {
        return Err("unsupported destination encoding");
    }
    let subaddress = bytes[2] == 1;
    let point = |slice: &[u8]| {
        let raw: [u8; 32] = slice.try_into().map_err(|_| "invalid public key length")?;
        CompressedPoint::from(raw)
            .decompress()
            .ok_or("invalid public key")
    };
    let address = MoneroAddress::new(
        network,
        if subaddress {
            AddressType::Subaddress
        } else {
            AddressType::Legacy
        },
        point(&bytes[3..35])?,
        point(&bytes[35..67])?,
    );
    if encode(network, &address.to_string())? != *bytes {
        return Err("destination checksum mismatch");
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use monero_wallet::{address::SubaddressIndex, ed25519::Scalar};
    use zeroize::Zeroizing;

    #[test]
    fn round_trip_preserves_network_type_and_keys() {
        let pair = crate::view_pair(&Zeroizing::new(Scalar::ONE)).unwrap();
        for network in [Network::Mainnet, Network::Testnet, Network::Stagenet] {
            for address in [
                pair.legacy_address(network),
                pair.subaddress(network, SubaddressIndex::new(0, 1).unwrap()),
            ] {
                let bytes = encode(network, &address.to_string()).unwrap();
                assert_eq!(decode(network, &bytes).unwrap(), address);
                assert_eq!(bytes[1], network_code(network));
                assert_eq!(bytes[2], u8::from(address.is_subaddress()));
                assert!(bytes[71..].iter().all(|b| *b == 0));
            }
        }
    }

    #[test]
    fn rejects_modified_checksum_network_version_and_padding() {
        let pair = crate::view_pair(&Zeroizing::new(Scalar::ONE)).unwrap();
        let bytes = encode(
            Network::Stagenet,
            &pair.legacy_address(Network::Stagenet).to_string(),
        )
        .unwrap();
        for index in [0, 1, 2, 3, 35, 67, 71, 95] {
            let mut changed = bytes;
            changed[index] ^= 1;
            assert!(
                decode(Network::Stagenet, &changed).is_err(),
                "accepted mutation at {index}"
            );
        }
        assert!(decode(Network::Mainnet, &bytes).is_err());
    }
}
