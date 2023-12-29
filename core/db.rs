use super::*;

macro_rules! tables {
    ($($name:ident: $tk:ty => $tv:ty)*) => {
        pub(crate) mod tables {
            use crate::*;
            $(pub const $name: redb::TableDefinition<$tk, $tv> = redb::TableDefinition::new(stringify!($name));)*
        }
    };
}

tables! {
    RAW_REQ: TimeBasedId => &[u8]
    // TODO bincode
    SESS_PKS: Uid => Vec<(&[u8; PUBLIC_KEY_LENGTH], SessPkExpires)> /* TODO sess info (ip, ua?) */
    REQ_WHICH_SESS: TimeBasedId => (Uid, &[u8; PUBLIC_KEY_LENGTH])
    USER_ROOT_PK: Uid => &[u8; PUBLIC_KEY_LENGTH]
    USER_ROOTKEY_SALT: Uid => (RegTime, &RootKeyPdkSalt)
    USER_FOREIGN: (Uid, ForeignId) => ForeignUid
    NEXT_UID: () => Uid
    REG_TICKET_SESS_PK: TicketUid => (&[u8; PUBLIC_KEY_LENGTH], SessPkExpires)
    REG_STATE: TicketUid => /* bincode */&[u8]
}

#[macro_export]
macro_rules! db_get {
    ($self:expr, $table:expr, $k:expr, $v:ident) => {
        let tr = $self.db.begin_read().expect("fatal: main db op failed");
        let table = tr.open_table($table).expect("fatal: main db op failed");
        let $v = redb::ReadableTable::get(&table, $k).expect("fatal: main db op failed");
    };
}

impl GlobalContext {
    pub(crate) fn db_init(path: std::path::PathBuf,db_mem_max: usize) -> redb::Database {
        let mut db = redb::Builder::new().set_cache_size(db_mem_max).create(path).expect("fatal: main db open failed");
        log::info!("main db opened with db_mem_max={}", db_mem_max);
        let passed = db.check_integrity().expect("main db suffered irreparable damage");
        if passed {
            log::info!("main db passed integrity check");
        } else {
            log::warn!("main db failed integrity check but repaired");
        }
        let tr = db.begin_write().expect("fatal: main db op failed");
        tr.open_table(tables::SESS_PKS);
        tr.commit().expect("fatal: main db op failed");
        db
    }

    pub(crate) fn db_first_insert<'k, 'v, K: redb::RedbKey, V: redb::RedbValue>(
        &self,
        table: redb::TableDefinition<K, V>,
        k: impl core::borrow::Borrow<K::SelfType<'k>>,
        v: impl core::borrow::Borrow<V::SelfType<'v>>,
    ) {
        // TODO more precise error
        let tr = self.db.begin_write().expect("fatal: main db op failed");
        {
            let mut table = tr.open_table(table).expect("fatal: main db op failed");
            let handle = table.insert(k, v).unwrap();
            assert!(handle.is_none(), "fatal: main db insert conflict");
        }
        tr.commit().expect("fatal: main db op failed");
    }

    // pub(crate) fn db_get<'k, 'v, K: redb::RedbKey, V: redb::RedbValue>(
    //     &self,
    //     table: redb::TableDefinition<K, V>,
    //     k: impl core::borrow::Borrow<K::SelfType<'k>>,
    // ) -> Option<V::SelfType<'v>> {
    //     let tr = self.db.begin_read().expect("fatal: main db op failed");
    //     let table = tr.open_table(table).expect("fatal: main db op failed");
    //     redb::ReadableTable::get(&table, k).expect("fatal: main db op failed")
    // }

    pub(crate) fn record_request(&self, id: TimeBasedId, req: &RawRequest) {
        // TODO config & buffering
        log::trace!("{}", serde_json::to_string(&req).unwrap());
        let encoded = bincode::serialize(&req).unwrap();
        self.db_first_insert(tables::RAW_REQ, id, encoded.as_slice());
        log::info!("req {:x} recorded", req.id);
    }
}
