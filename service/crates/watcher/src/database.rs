//! PostgreSQL TLS terminates inside the enclave; the parent forwards only TLS bytes.
use anyhow::{ensure, Context, Result};
use openssl::{
    ssl::{SslConnector, SslMethod, SslVerifyMode, SslVersion},
    x509::{store::X509StoreBuilder, X509},
};
use postgres::{config::SslMode, Client, Config as PgConfig};
use postgres_openssl::MakeTlsConnector;
use serde::Deserialize;
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use zz_core::{
    storage::{Cipher, PostgresStore},
    Id,
};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub tls_name: String,
    pub ca_pem: String,
    pub database: String,
    pub user: String,
}

fn validate(config: &Config) -> Result<()> {
    ensure!(
        !config.tls_name.is_empty()
            && config.tls_name.len() <= 253
            && config
                .tls_name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            && config.tls_name.parse::<IpAddr>().is_err(),
        "invalid database TLS hostname"
    );
    for value in [&config.database, &config.user] {
        ensure!(
            !value.is_empty()
                && value.len() <= 63
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_'),
            "invalid database identifier"
        );
    }
    ensure!(
        !config.ca_pem.is_empty() && config.ca_pem.len() <= 16384,
        "invalid database CA"
    );
    Ok(())
}

fn connector(config: &Config) -> Result<MakeTlsConnector> {
    validate(config)?;
    let certificates =
        X509::stack_from_pem(config.ca_pem.as_bytes()).context("invalid database CA")?;
    ensure!(!certificates.is_empty(), "database CA missing");
    let mut roots = X509StoreBuilder::new()?;
    for certificate in certificates {
        roots.add_cert(certificate)?;
    }
    let mut tls = SslConnector::builder(SslMethod::tls_client())?;
    tls.set_cert_store(roots.build());
    tls.set_verify(SslVerifyMode::PEER);
    tls.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    Ok(MakeTlsConnector::new(tls.build()))
}

/// Connect using an exact in-image CA and hostname, never host DNS or plaintext fallback.
#[cfg(test)]
fn connect_at(
    config: &Config,
    cipher: Cipher,
    vault: Id,
    initialize_now: bool,
    port: u16,
) -> Result<PostgresStore> {
    let client = connect_client_at(config, port)?;
    open(client, cipher, vault, initialize_now)
}

pub fn connect_client(config: &Config) -> Result<Client> {
    connect_client_at(config, 8446)
}

fn connect_client_at(config: &Config, port: u16) -> Result<Client> {
    let tls = connector(config)?;
    let mut pg = PgConfig::new();
    pg.host(&config.tls_name)
        .hostaddr(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .port(port)
        .user(&config.user)
        .dbname(&config.database)
        .ssl_mode(SslMode::Require)
        .connect_timeout(Duration::from_secs(10));
    pg.connect(tls).context("database TLS connection failed")
}

pub fn open(
    client: Client,
    cipher: Cipher,
    vault: Id,
    initialize_now: bool,
) -> Result<PostgresStore> {
    let mut store = PostgresStore::new(client, cipher);
    if initialize_now {
        store
            .migrate()
            .map_err(|_| anyhow::anyhow!("database migration failed"))?;
        store
            .initialize(vault)
            .map_err(|_| anyhow::anyhow!("database initialization failed"))?;
    } else {
        store
            .load(vault)
            .map_err(|_| anyhow::anyhow!("encrypted database state missing or invalid"))?;
    }
    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zz_core::storage::DataKeySource;
    struct TestKey(u8);
    impl DataKeySource for TestKey {
        fn data_key(
            &self,
        ) -> std::result::Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
            Ok([self.0; 32])
        }
    }
    #[test]
    fn rejects_unsafe_config_before_connect() {
        let mut config = Config {
            tls_name: "db.internal".into(),
            ca_pem: "not pem".into(),
            database: "bridge".into(),
            user: "bridge".into(),
        };
        assert!(connector(&config).is_err());
        config.tls_name = "127.0.0.1".into();
        assert!(validate(&config).is_err());
        config.tls_name = "db.internal".into();
        config.user = "x password=y".into();
        assert!(validate(&config).is_err());
    }

    #[test]
    fn tls_and_encrypted_initialization_restore() {
        let Ok(ca_path) = std::env::var("CWXMR_TEST_PG_CA") else {
            return;
        };
        let port = std::env::var("CWXMR_TEST_PG_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let config = Config {
            tls_name: std::env::var("CWXMR_TEST_PG_TLS_NAME")
                .unwrap_or_else(|_| "postgres.test".into()),
            ca_pem: std::fs::read_to_string(ca_path).unwrap(),
            database: "postgres".into(),
            user: std::env::var("CWXMR_TEST_PG_USER").unwrap(),
        };
        let mut vault_id = [0u8; 32];
        openssl::rand::rand_bytes(&mut vault_id).unwrap();
        let vault = Id(vault_id);
        let cipher = || Cipher::new(&TestKey(55)).unwrap();
        connect_at(&config, cipher(), vault, true, port).unwrap();
        connect_at(&config, cipher(), vault, false, port).unwrap();
        assert!(connect_at(&config, cipher(), vault, true, port).is_err());
        assert!(connect_at(&config, cipher(), Id([0x52; 32]), false, port).is_err());
        assert!(connect_at(
            &config,
            Cipher::new(&TestKey(56)).unwrap(),
            vault,
            false,
            port
        )
        .is_err());
        let mut wrong_name = config.clone();
        wrong_name.tls_name = "wrong.test".into();
        assert!(connect_at(&wrong_name, cipher(), vault, false, port).is_err());
        let identity = zz_watcher::attestation::Identity::generate().unwrap();
        let domain = zz_watcher::attestation::BindingDomain {
            chain_id: 11155111,
            registry: "11".repeat(20),
            bridge: "22".repeat(20),
            policy_version: 1,
        };
        let identity_vault = Id(zz_watcher::attestation::decode::<32>(
            &identity.public().unwrap().vault_id,
        )
        .unwrap());
        let store = connect_at(&config, cipher(), identity_vault, true, port).unwrap();
        let mut deposits = zz_watcher::deposits::Deposits::open(store, &identity, &domain).unwrap();
        let original = deposits.issue([1; 20], Id([2; 32])).unwrap();
        drop(deposits);
        let store = connect_at(&config, cipher(), identity_vault, false, port).unwrap();
        let mut deposits = zz_watcher::deposits::Deposits::open(store, &identity, &domain).unwrap();
        assert_eq!(
            deposits.issue([1; 20], Id([2; 32])).unwrap().id,
            original.id
        );
        assert!(deposits.issue([3; 20], Id([2; 32])).is_err());
        if let Ok(wrong_ca) = std::env::var("CWXMR_TEST_PG_WRONG_CA") {
            let mut untrusted = config.clone();
            untrusted.ca_pem = std::fs::read_to_string(wrong_ca).unwrap();
            assert!(connect_at(&untrusted, cipher(), vault, false, port).is_err());
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let plain_port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0u8; 8];
            socket.read_exact(&mut request).unwrap();
            assert_eq!(request, [0, 0, 0, 8, 4, 210, 22, 47]);
            socket.write_all(b"N").unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut extra = [0u8; 1];
            assert_eq!(socket.read(&mut extra).unwrap_or(0), 0);
        });
        assert!(connect_at(&config, cipher(), vault, false, plain_port).is_err());
        server.join().unwrap();
    }
}
