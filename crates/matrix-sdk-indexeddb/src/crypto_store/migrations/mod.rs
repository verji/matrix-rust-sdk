// Copyright 2023 The Matrix.org Foundation C.I.C.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use indexed_db_futures::{prelude::*, web_sys::DomException};
use tracing::info;
use wasm_bindgen::JsValue;

use crate::{
    crypto_store::{indexeddb_serializer::IndexeddbSerializer, keys, Result},
    IndexeddbCryptoStoreError,
};

mod old_keys;
mod v5_to_v7;
mod v7;
mod v7_to_v8;
mod v8_to_v10;

/// Open the indexeddb with the given name, upgrading it to the latest version
/// of the schema if necessary.
pub async fn open_and_upgrade_db(
    name: &str,
    serializer: &IndexeddbSerializer,
) -> Result<IdbDatabase, IndexeddbCryptoStoreError> {
    // This is all a bit of a hack. Some of the version migrations require a data
    // migration, which has to be done via async APIs; however, the
    // JS `upgrade_needed` mechanism does not allow for async calls.
    //
    // Start by finding out what the existing version is, if any.
    let db = IdbDatabase::open(name)?.await?;
    let old_version = db.version() as u32;
    db.close();

    // Perform the schema-only migrations
    if old_version < 5 {
        migrate_schema_up_to_v5(name).await?;
    }

    // If we have yet to complete the migration to V7, migrate the schema to V6
    // (if necessary), and then migrate any remaining data.
    if old_version < 6 {
        v5_to_v7::migrate_schema_up_to_v6(name).await?;
    }
    if old_version < 7 {
        v5_to_v7::prepare_data_for_v7(name, serializer).await?;

        // Now we can safely complete the migration to V7 which will drop the old store.
        v5_to_v7::migrate_schema_for_v7(name).await?;
    }

    // Migrate to v8, keeping the same schema but fixing the keys in
    // inbound_group_sessions2
    if old_version < 8 {
        v7_to_v8::prepare_data_for_v8(name, serializer).await?;
        v7_to_v8::migrate_schema_for_v8(name).await?;
    }

    // Migrate to v10, moving from inbound_group_sessions2 to
    // inbound_group_sessions3, which has smaller values by storing JavaScript
    // objects instead of serialized arrays, and base64 strings instead of
    // arrays of ints. inbound_group_sessions3 also has backed_up_to, which is
    // indexed.
    if old_version < 9 {
        v8_to_v10::upgrade_scheme_to_v9_create_inbound_group_sessions3(name).await?;
    }
    if old_version < 10 {
        v8_to_v10::migrate_data_before_v10_populate_inbound_group_sessions3(name, serializer)
            .await?;
        v8_to_v10::upgrade_scheme_to_v10_delete_inbound_group_sessions2(name).await?;
    }

    // We know we've upgraded to v10 now, so we can open the DB at that version and
    // return it
    Ok(IdbDatabase::open_u32(name, 10)?.await?)
}

async fn migrate_schema_up_to_v5(name: &str) -> Result<(), DomException> {
    do_schema_upgrade(name, 5, |db, old_version| {
        // An old_version of 1 could either mean actually the first version of the
        // schema, or a completely empty schema that has been created with a
        // call to `IdbDatabase::open` with no explicit "version". So, to determine
        // if we need to create the V1 stores, we actually check if the schema is empty.
        if db.object_store_names().next().is_none() {
            migrate_stores_to_v1(db)?;
        }

        if old_version < 2 {
            migrate_stores_to_v2(db)?;
        }

        if old_version < 3 {
            migrate_stores_to_v3(db)?;
        }

        if old_version < 4 {
            migrate_stores_to_v4(db)?;
        }

        if old_version < 5 {
            migrate_stores_to_v5(db)?;
        }

        Ok(())
    })
    .await
}

fn migrate_stores_to_v1(db: &IdbDatabase) -> Result<(), DomException> {
    db.create_object_store(keys::CORE)?;
    db.create_object_store(keys::SESSION)?;

    db.create_object_store(old_keys::INBOUND_GROUP_SESSIONS_V1)?;
    db.create_object_store(keys::OUTBOUND_GROUP_SESSIONS)?;
    db.create_object_store(keys::TRACKED_USERS)?;
    db.create_object_store(keys::OLM_HASHES)?;
    db.create_object_store(keys::DEVICES)?;

    db.create_object_store(keys::IDENTITIES)?;
    db.create_object_store(keys::BACKUP_KEYS)?;

    Ok(())
}

fn migrate_stores_to_v2(db: &IdbDatabase) -> Result<(), DomException> {
    // We changed how we store inbound group sessions, the key used to
    // be a tuple of `(room_id, sender_key, session_id)` now it's a
    // tuple of `(room_id, session_id)`
    //
    // Let's just drop the whole object store.
    db.delete_object_store(old_keys::INBOUND_GROUP_SESSIONS_V1)?;
    db.create_object_store(old_keys::INBOUND_GROUP_SESSIONS_V1)?;

    db.create_object_store(keys::ROOM_SETTINGS)?;

    Ok(())
}

fn migrate_stores_to_v3(db: &IdbDatabase) -> Result<(), DomException> {
    // We changed the way we store outbound session.
    // ShareInfo changed from a struct to an enum with struct variant.
    // Let's just discard the existing outbounds
    db.delete_object_store(keys::OUTBOUND_GROUP_SESSIONS)?;
    db.create_object_store(keys::OUTBOUND_GROUP_SESSIONS)?;

    // Support for MSC2399 withheld codes
    db.create_object_store(keys::DIRECT_WITHHELD_INFO)?;

    Ok(())
}

fn migrate_stores_to_v4(db: &IdbDatabase) -> Result<(), DomException> {
    db.create_object_store(keys::SECRETS_INBOX)?;
    Ok(())
}

fn migrate_stores_to_v5(db: &IdbDatabase) -> Result<(), DomException> {
    // Create a new store for outgoing secret requests
    let object_store = db.create_object_store(keys::GOSSIP_REQUESTS)?;

    let mut params = IdbIndexParameters::new();
    params.unique(false);
    object_store.create_index_with_params(
        keys::GOSSIP_REQUESTS_UNSENT_INDEX,
        &IdbKeyPath::str("unsent"),
        &params,
    )?;

    let mut params = IdbIndexParameters::new();
    params.unique(true);
    object_store.create_index_with_params(
        keys::GOSSIP_REQUESTS_BY_INFO_INDEX,
        &IdbKeyPath::str("info"),
        &params,
    )?;

    if db.object_store_names().any(|n| n == "outgoing_secret_requests") {
        // Delete the old store names. We just delete any existing requests.
        db.delete_object_store("outgoing_secret_requests")?;
        db.delete_object_store("unsent_secret_requests")?;
        db.delete_object_store("secret_requests_by_info")?;
    }

    Ok(())
}

async fn do_schema_upgrade<F>(name: &str, version: u32, f: F) -> Result<(), DomException>
where
    F: Fn(&IdbDatabase, u32) -> Result<(), JsValue> + 'static,
{
    info!("IndexeddbCryptoStore upgrade schema -> v{version} starting");
    let mut db_req: OpenDbRequest = IdbDatabase::open_u32(name, version)?;

    db_req.set_on_upgrade_needed(Some(move |evt: &IdbVersionChangeEvent| {
        // Even if the web-sys bindings expose the version as a f64, the IndexedDB API
        // works with an unsigned integer.
        // See <https://github.com/rustwasm/wasm-bindgen/issues/1149>
        let old_version = evt.old_version() as u32;

        // Run the upgrade code we were supplied
        f(evt.db(), old_version)
    }));

    let db = db_req.await?;
    db.close();
    info!("IndexeddbCryptoStore upgrade schema -> v{version} complete");
    Ok(())
}

#[cfg(all(test, target_arch = "wasm32"))]
mod tests {
    use std::{future::Future, sync::Arc};

    use indexed_db_futures::prelude::*;
    use matrix_sdk_common::js_tracing::make_tracing_subscriber;
    use matrix_sdk_crypto::{
        olm::{InboundGroupSession, SessionKey},
        store::CryptoStore,
        types::EventEncryptionAlgorithm,
        vodozemac::{Curve25519PublicKey, Curve25519SecretKey, Ed25519PublicKey, Ed25519SecretKey},
    };
    use matrix_sdk_store_encryption::StoreCipher;
    use matrix_sdk_test::async_test;
    use ruma::{room_id, OwnedRoomId, RoomId};
    use tracing_subscriber::util::SubscriberInitExt;
    use web_sys::console;

    use super::v7::InboundGroupSessionIndexedDbObject2;
    use crate::{
        crypto_store::{
            indexeddb_serializer::MaybeEncrypted, migrations::*, InboundGroupSessionIndexedDbObject,
        },
        IndexeddbCryptoStore,
    };

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    /// Adjust this to test do a more comprehensive perf test
    const NUM_RECORDS_FOR_PERF: usize = 2_000;

    /// Make lots of sessions and see how long it takes to count them in v8
    #[async_test]
    async fn count_lots_of_sessions_v8() {
        let cipher = Arc::new(StoreCipher::new().unwrap());
        let serializer = IndexeddbSerializer::new(Some(cipher.clone()));
        // Session keys are slow to create, so make one upfront and use it for every
        // session
        let session_key = create_session_key();

        // Create lots of InboundGroupSessionIndexedDbObject2 objects
        let mut objects = Vec::with_capacity(NUM_RECORDS_FOR_PERF);
        for i in 0..NUM_RECORDS_FOR_PERF {
            objects.push(
                create_inbound_group_sessions2_record(i, &session_key, &cipher, &serializer).await,
            );
        }

        // Create a DB with an inbound_group_sessions2 store
        let db_prefix = "count_lots_of_sessions_v8";
        let db = create_db(db_prefix).await;
        let transaction = create_transaction(&db, db_prefix).await;
        let store = create_store(&transaction, db_prefix).await;

        // Check how long it takes to insert these records
        measure_performance("Inserting", "v8", NUM_RECORDS_FOR_PERF, || async {
            for (key, session_js) in objects.iter() {
                store.add_key_val(key, session_js).unwrap().await.unwrap();
            }
        })
        .await;

        // Check how long it takes to count these records
        measure_performance("Counting", "v8", NUM_RECORDS_FOR_PERF, || async {
            store.count().unwrap().await.unwrap();
        })
        .await;
    }

    /// Make lots of sessions and see how long it takes to count them in v10
    #[async_test]
    async fn count_lots_of_sessions_v10() {
        let cipher = Arc::new(StoreCipher::new().unwrap());
        let serializer = IndexeddbSerializer::new(Some(cipher.clone()));
        // Session keys are slow to create, so make one upfront and use it for every
        // session
        let session_key = create_session_key();

        // Create lots of InboundGroupSessionIndexedDbObject objects
        let mut objects = Vec::with_capacity(NUM_RECORDS_FOR_PERF);
        for i in 0..NUM_RECORDS_FOR_PERF {
            objects.push(
                create_inbound_group_sessions3_record(i, &session_key, &cipher, &serializer).await,
            );
        }

        // Create a DB with an inbound_group_sessions3 store
        let db_prefix = "count_lots_of_sessions_v8";
        let db = create_db(db_prefix).await;
        let transaction = create_transaction(&db, db_prefix).await;
        let store = create_store(&transaction, db_prefix).await;

        // Check how long it takes to insert these records
        measure_performance("Inserting", "v10", NUM_RECORDS_FOR_PERF, || async {
            for (key, session_js) in objects.iter() {
                store.add_key_val(key, session_js).unwrap().await.unwrap();
            }
        })
        .await;

        // Check how long it takes to count these records
        measure_performance("Counting", "v10", NUM_RECORDS_FOR_PERF, || async {
            store.count().unwrap().await.unwrap();
        })
        .await;
    }

    async fn create_db(db_prefix: &str) -> IdbDatabase {
        let db_name = format!("{db_prefix}::matrix-sdk-crypto");
        let store_name = format!("{db_prefix}_store");
        let mut db_req: OpenDbRequest = IdbDatabase::open_u32(&db_name, 1).unwrap();
        db_req.set_on_upgrade_needed(Some(
            move |evt: &IdbVersionChangeEvent| -> Result<(), JsValue> {
                evt.db().create_object_store(&store_name)?;
                Ok(())
            },
        ));
        db_req.await.unwrap()
    }

    async fn create_transaction<'a>(db: &'a IdbDatabase, db_prefix: &str) -> IdbTransaction<'a> {
        let store_name = format!("{db_prefix}_store");
        db.transaction_on_one_with_mode(&store_name, IdbTransactionMode::Readwrite).unwrap()
    }

    async fn create_store<'a>(
        transaction: &'a IdbTransaction<'a>,
        db_prefix: &str,
    ) -> IdbObjectStore<'a> {
        let store_name = format!("{db_prefix}_store");
        transaction.object_store(&store_name).unwrap()
    }

    fn create_session_key() -> SessionKey {
        SessionKey::from_base64(
            "\
            AgAAAADBy9+YIYTIqBjFT67nyi31gIOypZQl8day2hkhRDCZaHoG+cZh4tZLQIAZimJail0\
            0zq4DVJVljO6cZ2t8kIto/QVk+7p20Fcf2nvqZyL2ZCda2Ei7VsqWZHTM/gqa2IU9+ktkwz\
            +KFhENnHvDhG9f+hjsAPZd5mTTpdO+tVcqtdWhX4dymaJ/2UpAAjuPXQW+nXhQWQhXgXOUa\
            JCYurJtvbCbqZGeDMmVIoqukBs2KugNJ6j5WlTPoeFnMl6Guy9uH2iWWxGg8ZgT2xspqVl5\
            CwujjC+m7Dh1toVkvu+bAw\
            ",
        )
        .unwrap()
    }

    async fn create_inbound_group_sessions2_record(
        i: usize,
        session_key: &SessionKey,
        cipher: &Arc<StoreCipher>,
        serializer: &IndexeddbSerializer,
    ) -> (JsValue, JsValue) {
        let session = create_inbound_group_session(i, session_key);
        let pickled_session = session.pickle().await;
        let session_dbo = InboundGroupSessionIndexedDbObject2 {
            pickled_session: cipher.encrypt_value(&pickled_session).unwrap(),
            needs_backup: false,
        };
        let session_js: JsValue = serde_wasm_bindgen::to_value(&session_dbo).unwrap();

        let key = serializer.encode_key(
            old_keys::INBOUND_GROUP_SESSIONS_V2,
            (&session.room_id, session.session_id()),
        );

        (key, session_js)
    }

    async fn create_inbound_group_sessions3_record(
        i: usize,
        session_key: &SessionKey,
        cipher: &Arc<StoreCipher>,
        serializer: &IndexeddbSerializer,
    ) -> (JsValue, JsValue) {
        let session = create_inbound_group_session(i, session_key);
        let pickled_session = session.pickle().await;
        let session_dbo = InboundGroupSessionIndexedDbObject {
            pickled_session: MaybeEncrypted::Encrypted(
                cipher.encrypt_value_base64_typed(&pickled_session).unwrap(),
            ),
            needs_backup: false,
            backed_up_to: -1,
        };
        let session_js: JsValue = serde_wasm_bindgen::to_value(&session_dbo).unwrap();

        let key = serializer.encode_key(
            old_keys::INBOUND_GROUP_SESSIONS_V2,
            (&session.room_id, session.session_id()),
        );

        (key, session_js)
    }

    async fn measure_performance<Fut, R>(
        name: &str,
        schema: &str,
        num_records: usize,
        f: impl Fn() -> Fut,
    ) -> R
    where
        Fut: Future<Output = R>,
    {
        let window = web_sys::window().expect("should have a window in this context");
        let performance = window.performance().expect("performance should be available");
        let start = performance.now();

        let ret = f().await;

        let elapsed = performance.now() - start;
        console::log_1(
            &format!("{name} {num_records} records with {schema} schema took {elapsed:.2}ms.")
                .into(),
        );

        ret
    }

    /// Create an example InboundGroupSession of known size
    fn create_inbound_group_session(i: usize, session_key: &SessionKey) -> InboundGroupSession {
        let sender_key = Curve25519PublicKey::from_bytes([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ]);
        let signing_key = Ed25519PublicKey::from_slice(&[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ])
        .unwrap();
        let room_id: OwnedRoomId = format!("!a{i}:b.co").try_into().unwrap();
        let encryption_algorithm = EventEncryptionAlgorithm::MegolmV1AesSha2;
        let history_visibility = None;

        InboundGroupSession::new(
            sender_key,
            signing_key,
            &room_id,
            session_key,
            encryption_algorithm,
            history_visibility,
        )
        .unwrap()
    }

    /// Test migrating `inbound_group_sessions` data from store v5 to latest,
    /// on a store with encryption disabled.
    #[async_test]
    async fn test_v8_v10_migration_unencrypted() {
        test_v8_v10_migration_with_cipher("test_v8_migration_unencrypted", None).await
    }

    /// Test migrating `inbound_group_sessions` data from store v5 to store v8,
    /// on a store with encryption enabled.
    #[async_test]
    async fn test_v8_v10_migration_encrypted() {
        let cipher = StoreCipher::new().unwrap();
        test_v8_v10_migration_with_cipher("test_v8_migration_encrypted", Some(Arc::new(cipher)))
            .await;
    }

    /// Helper function for `test_v8_v10_migration_{un,}encrypted`: test
    /// migrating `inbound_group_sessions` data from store v5 to store v10.
    async fn test_v8_v10_migration_with_cipher(
        db_prefix: &str,
        store_cipher: Option<Arc<StoreCipher>>,
    ) {
        let _ = make_tracing_subscriber(None).try_init();
        let db_name = format!("{db_prefix:0}::matrix-sdk-crypto");

        // delete the db in case it was used in a previous run
        let _ = IdbDatabase::delete_by_name(&db_name);

        // Given a DB with data in it as it was at v5
        let room_id = room_id!("!test:localhost");
        let (backed_up_session, not_backed_up_session) = create_sessions(&room_id);
        populate_v5_db(
            &db_name,
            store_cipher.clone(),
            &[&backed_up_session, &not_backed_up_session],
        )
        .await;

        // When I open a store based on that DB, triggering an upgrade
        let store =
            IndexeddbCryptoStore::open_with_store_cipher(&db_prefix, store_cipher).await.unwrap();

        // Then I can find the sessions using their keys and their info is correct
        let fetched_backed_up_session = store
            .get_inbound_group_session(room_id, backed_up_session.session_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched_backed_up_session.session_id(), backed_up_session.session_id());

        let fetched_not_backed_up_session = store
            .get_inbound_group_session(room_id, not_backed_up_session.session_id())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fetched_not_backed_up_session.session_id(), not_backed_up_session.session_id());

        // For v8: the backed_up info is preserved
        assert!(fetched_backed_up_session.backed_up());
        assert!(!fetched_not_backed_up_session.backed_up());

        // For v10: they have the backed_up_to property and it is indexed
        assert_matches_v10_schema(db_name, store, fetched_backed_up_session).await;
    }

    async fn assert_matches_v10_schema(
        db_name: String,
        store: IndexeddbCryptoStore,
        fetched_backed_up_session: InboundGroupSession,
    ) {
        let db = IdbDatabase::open(&db_name).unwrap().await.unwrap();
        assert_eq!(db.version(), 10.0);
        let transaction = db.transaction_on_one("inbound_group_sessions3").unwrap();
        let raw_store = transaction.object_store("inbound_group_sessions3").unwrap();
        let key = store.serializer.encode_key(
            keys::INBOUND_GROUP_SESSIONS_V3,
            (fetched_backed_up_session.room_id(), fetched_backed_up_session.session_id()),
        );
        let idb_object: InboundGroupSessionIndexedDbObject =
            serde_wasm_bindgen::from_value(raw_store.get(&key).unwrap().await.unwrap().unwrap())
                .unwrap();

        assert_eq!(idb_object.backed_up_to, -1);
        assert!(raw_store.index_names().find(|idx| idx == "backed_up_to").is_some());

        db.close();
    }

    fn create_sessions(room_id: &RoomId) -> (InboundGroupSession, InboundGroupSession) {
        let curve_key = Curve25519PublicKey::from(&Curve25519SecretKey::new());
        let ed_key = Ed25519SecretKey::new().public_key();

        let backed_up_session = InboundGroupSession::new(
            curve_key,
            ed_key,
            room_id,
            &SessionKey::from_base64(
                "AgAAAABTyn3CR8mzAxhsHH88td5DrRqfipJCnNbZeMrfzhON6O1Cyr9ewx/sDFLO6\
                 +NvyW92yGvMub7nuAEQb+SgnZLm7nwvuVvJgSZKpoJMVliwg8iY9TXKFT286oBtT2\
                 /8idy6TcpKax4foSHdMYlZXu5zOsGDdd9eYnYHpUEyDT0utuiaakZM3XBMNLEVDj9\
                 Ps929j1FGgne1bDeFVoty2UAOQK8s/0JJigbKSu6wQ/SzaCYpE/LD4Egk2Nxs1JE2\
                 33ii9J8RGPYOp7QWl0kTEc8mAlqZL7mKppo9AwgtmYweAg",
            )
            .unwrap(),
            EventEncryptionAlgorithm::MegolmV1AesSha2,
            None,
        )
        .unwrap();
        backed_up_session.mark_as_backed_up();

        let not_backed_up_session = InboundGroupSession::new(
            curve_key,
            ed_key,
            room_id,
            &SessionKey::from_base64(
                "AgAAAACO1PjBdqucFUcNFU6JgXYAi7KMeeUqUibaLm6CkHJcMiDTFWq/K5SFAukJc\
                 WjeyOpnZr4vpezRlbvNaQpNPMub2Cs2u14fHj9OpKFD7c4hFS4j94q4pTLZly3qEV\
                 BIjWdOpcIVfN7QVGVIxYiI6KHEddCHrNCo9fc8GUdfzrMnmUooQr/m4ZAkRdErzUH\
                 uUAlUBwOKcPi7Cs/KrMw/sHCRDkTntHZ3BOrzJsAVbHUgq+8/Sqy3YE+CX6uEnig+\
                 1NWjZD9f1vvXnSKKDdHj1927WFMFZ/yYc24607zEVUaODQ",
            )
            .unwrap(),
            EventEncryptionAlgorithm::MegolmV1AesSha2,
            None,
        )
        .unwrap();

        (backed_up_session, not_backed_up_session)
    }

    async fn populate_v5_db(
        db_name: &str,
        store_cipher: Option<Arc<StoreCipher>>,
        session_entries: &[&InboundGroupSession],
    ) {
        // Schema V7 migrated the inbound group sessions to a new format.
        // To test, first create a database and populate it with the *old* style of
        // entry.
        let db = create_v5_db(&db_name).await.unwrap();

        let serializer = IndexeddbSerializer::new(store_cipher);

        let txn = db
            .transaction_on_one_with_mode(
                old_keys::INBOUND_GROUP_SESSIONS_V1,
                IdbTransactionMode::Readwrite,
            )
            .unwrap();
        let sessions = txn.object_store(old_keys::INBOUND_GROUP_SESSIONS_V1).unwrap();
        for session in session_entries {
            let room_id = session.room_id();
            let session_id = session.session_id();
            let key =
                serializer.encode_key(old_keys::INBOUND_GROUP_SESSIONS_V1, (room_id, session_id));
            let pickle = session.pickle().await;

            sessions.put_key_val(&key, &serializer.serialize_value(&pickle).unwrap()).unwrap();
        }
        txn.await.into_result().unwrap();

        // now close our DB, reopen it properly, and check that we can still read our
        // data.
        db.close();
    }

    async fn create_v5_db(name: &str) -> std::result::Result<IdbDatabase, DomException> {
        let mut db_req: OpenDbRequest = IdbDatabase::open_u32(name, 5)?;
        db_req.set_on_upgrade_needed(Some(|evt: &IdbVersionChangeEvent| -> Result<(), JsValue> {
            let db = evt.db();
            migrate_stores_to_v1(db)?;
            migrate_stores_to_v2(db)?;
            migrate_stores_to_v3(db)?;
            migrate_stores_to_v4(db)?;
            migrate_stores_to_v5(db)?;
            Ok(())
        }));
        db_req.await
    }
}
