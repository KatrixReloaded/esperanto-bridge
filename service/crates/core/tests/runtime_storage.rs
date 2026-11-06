use std::error::Error;
use zz_core::{
    storage::{Cipher, DataKeySource, PostgresStore},
    AtomicAmount, Id,
};
struct Key;
impl DataKeySource for Key {
    fn data_key(&self) -> Result<[u8; 32], Box<dyn Error + Send + Sync>> {
        Ok([71; 32])
    }
}
#[test]
fn synchronous_storage_inside_both_tokio_runtime_flavors() {
    let Ok(url) = std::env::var("CWXMR_TEST_DATABASE_URL") else {
        return;
    };
    for multi_thread in [false, true] {
        // Establish both independent sessions before entering Tokio, matching runtime startup.
        let connect = || {
            PostgresStore::new(
                postgres::Client::connect(&url, postgres::NoTls).unwrap(),
                Cipher::new(&Key).unwrap(),
            )
        };
        let mut store = connect();
        let mut contender = connect();
        let mut id = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
        let id = Id(id);
        let mut builder = if multi_thread {
            tokio::runtime::Builder::new_multi_thread()
        } else {
            tokio::runtime::Builder::new_current_thread()
        };
        let runtime = builder.enable_all().build().unwrap();
        runtime.block_on(async {
            store.migrate().unwrap();
            store.initialize(id).unwrap();
            assert!(store.initialize(id).is_err());
            store.acquire_stagenet_poc_lease(id).unwrap();
            store.check_stagenet_poc_lease(id).unwrap();
            assert!(contender.acquire_stagenet_poc_lease(id).is_err());
            assert!(store.load(id).unwrap().mint_results.is_empty());
            let result = store
                .update(id, |state| {
                    state.mint_results.push((id, AtomicAmount(7)));
                    Ok(7)
                })
                .unwrap();
            assert_eq!(result, 7);
            assert_eq!(
                store.load(id).unwrap().mint_results,
                vec![(id, AtomicAmount(7))]
            );
            assert!(store
                .update::<()>(id, |state| {
                    state.mint_results.push((id, AtomicAmount(99)));
                    Err("deliberate transition failure".into())
                })
                .is_err());
            assert_eq!(
                contender.load(id).unwrap().mint_results,
                vec![(id, AtomicAmount(7))]
            );
            store.check_stagenet_poc_lease(id).unwrap();
            assert!(contender.acquire_stagenet_poc_lease(id).is_err());
            // Client::drop drives its internal runtime too. Session release must finish before
            // a different cooperative writer takes the lease, without reconnecting the store.
            drop(store);
            contender.acquire_stagenet_poc_lease(id).unwrap();
            contender.check_stagenet_poc_lease(id).unwrap();
            drop(contender);
        });
    }
}
