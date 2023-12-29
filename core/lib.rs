#![allow(unused)]

use bytes::Bytes;
use bytestring::ByteString;
use serde::{Serialize, Deserialize};
use ed25519_dalek::{VerifyingKey, Signature, PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};

pub type Uid = u64;
pub type ServiceName = ByteString;
pub type MethodName = ByteString;
pub type TimeBasedId = u128;
pub type TsSecs = u64;
pub type TsNanos = u32;

pub struct Session<'a> {
    pk: &'a [u8; PUBLIC_KEY_LENGTH],
    expire: TsSecs,
}

macro_rules! tables {
    ($($name:ident: $tk:ty => $tv:ty)*) => {
        mod tables {
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

pub struct GlobalConfig<'a> {
    pub root: &'a std::path::Path,
    pub db_mem_max: Option<usize>,
    pub api_path: Option<&'static str>,
}

pub struct GlobalContext {
    db: redb::Database,
    event_path: std::path::PathBuf,
    api_path: &'static str,
}

pub struct IncomingRequest {
    pub time: std::time::SystemTime,
    pub remote_addr: std::net::SocketAddr,
    pub header: http::request::Parts,
    pub payload: Bytes,
}

#[derive(Serialize)]
pub struct RawTime {
    // dir: bool,
    secs: TsSecs,
    nanos: TsNanos,
}

impl From<std::time::SystemTime> for RawTime {
    fn from(value: std::time::SystemTime) -> Self {
        let res = value.duration_since(std::time::UNIX_EPOCH);
        let dir = res.is_ok();
        assert!(dir, "time before unix epoch");
        let dur = res.unwrap_or_else(|err| err.duration());
        let secs = dur.as_secs();
        let nanos = dur.subsec_nanos();
        Self { secs, nanos }
    }
}

impl RawTime {
    fn time_based_id(&self) -> TimeBasedId {
        let mut buf = [0; 16];
        // buf[0] = self.dir as u8;
        buf[0..8].copy_from_slice(&self.secs.to_be_bytes());
        buf[8..12].copy_from_slice(&self.nanos.to_be_bytes());
        // TODO seeding?
        cshake::Squeeze::squeeze(&mut cshake::rand::thread_rng(), &mut buf[12..16]);
        u128::from_be_bytes(buf)
    }
}

#[derive(Serialize)]
pub struct RawRequest {
    pub id: TimeBasedId,
    pub time: RawTime,
    pub remote_addr: std::net::SocketAddr,
    #[serde(with = "http_serde::method")]
    pub method: http::Method,
    #[serde(with = "http_serde::uri")]
    pub uri: http::Uri,
    #[serde(with = "http_serde::version")]
    pub version: http::Version,
    #[serde(with = "http_serde::header_map")]
    pub headers: http::HeaderMap,
    pub payload: Bytes,
}

impl From<IncomingRequest> for RawRequest {
    fn from(IncomingRequest { time, remote_addr, header, payload }: IncomingRequest) -> Self {
        let http::request::Parts { method, uri, version, headers, extensions, .. } = header;
        assert!(extensions.is_empty(), "request has additional data");
        let time: RawTime = time.into();
        let id = time.time_based_id();
        Self { id, time, remote_addr, method, version, uri, headers, payload }
    }
}

#[derive(Serialize)]
pub struct RequestAuch {
    // TODO rootkey salt rather than uid?
    pub uid: Uid,
    pub signature: Signature,
}

#[derive(Serialize)]
pub struct Request {
    pub id: TimeBasedId,
    pub auch: Option<RequestAuch>,
    pub service: ServiceName,
    pub method: MethodName,
    pub payload: Bytes,
}

#[derive(Serialize)]
pub struct Response {
    pub code: Code,
    pub data: Option<serde_json::Value>,
}

#[repr(u16)]
#[derive(serde_repr::Serialize_repr)]
pub enum Code {
    Succeed = 0,
    NoAvailableSessions = 1001,
    SessionVerifyFailed = 1002,
}

impl Code {
    const fn msg(&self) -> &'static str {
        use Code::*;
        match self {
            Succeed => "",
            NoAvailableSessions => "no available sessions",
            SessionVerifyFailed => "session verify failed",
        }
    }
}

macro_rules! db_get {
    ($self:expr, $table:expr, $k:expr, $v:ident) => {
        let tr = $self.db.begin_read().expect("fatal: main db op failed");
        let table = tr.open_table($table).expect("fatal: main db op failed");
        let $v = redb::ReadableTable::get(&table, $k).expect("fatal: main db op failed");
    };
}

impl GlobalContext {
    pub fn init(GlobalConfig { root, db_mem_max, api_path }: GlobalConfig) -> Self {
        let db_mem_max = db_mem_max.unwrap_or(256 * 2usize.pow(20) /* 256MiB */);
        let api_path = api_path.unwrap_or("/__dawnflame_api");

        let mut db = redb::Builder::new().set_cache_size(db_mem_max).create(root.join("main-db")).expect("fatal: main db open failed");
        log::info!("main db opened with db_mem_max={}", db_mem_max);
        let event_path = root.join("events");
        let passed = db.check_integrity().expect("main db suffered irreparable damage");
        if passed {
            log::info!("main db passed integrity check");
        } else {
            log::warn!("main db failed integrity check but repaired");
        }
        let _self = Self { db, event_path, api_path };
        _self.db_create_tables();
        _self
    }

    fn db_create_tables(&self) {
        let tr = self.db.begin_write().expect("fatal: main db op failed");
        tr.open_table(tables::SESS_PKS);
        tr.commit().expect("fatal: main db op failed");
    }

    fn db_first_insert<'k, 'v, K: redb::RedbKey, V: redb::RedbValue>(
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

    // fn db_get<'k, 'v, K: redb::RedbKey, V: redb::RedbValue>(
    //     &self,
    //     table: redb::TableDefinition<K, V>,
    //     k: impl core::borrow::Borrow<K::SelfType<'k>>,
    // ) -> Option<V::SelfType<'v>> {
    //     let tr = self.db.begin_read().expect("fatal: main db op failed");
    //     let table = tr.open_table(table).expect("fatal: main db op failed");
    //     redb::ReadableTable::get(&table, k).expect("fatal: main db op failed")
    // }

    fn record_request(&self, id: TimeBasedId, req: &RawRequest) {
        // TODO config & buffering
        log::trace!("{}", serde_json::to_string(&req).unwrap());
        let encoded = bincode::serialize(&req).unwrap();
        self.db_first_insert(tables::RAW_REQ, id, encoded.as_slice());
        log::info!("req {:x} recorded", req.id);
    }

    fn gateway(&self, req: RawRequest) -> Result<Request, http::Response<()>> {
        // TODO reason in log
        macro_rules! reject {
            ($status:ident) => {
                log::info!("req {:x} rejected", req.id);
                return Err(http::Response::builder().status(http::StatusCode::$status).body(()).unwrap());
            };
        }

        // TODO reason in payload?
        macro_rules! else_reject {
            (Some($v:expr)) => {
                if let Some(__v) = $v { __v } else { reject!(BAD_REQUEST); }
            };
            (Ok($v:expr)) => {
                if let Ok(__v) = $v { __v } else { reject!(BAD_REQUEST); }
            };
        }

        macro_rules! header {
            (s $($name:ident $key:expr)*) => {$(
                let $name = else_reject!(Ok(else_reject!(Some(req.headers.get($key))).to_str()));
            )*};
            (b $($name:ident $key:expr)*) => {$(
                let $name = else_reject!(Some(req.headers.get($key)));
            )*};
            (bs $($name:ident $key:expr)*) => {$(
                let $name = ByteString::from(else_reject!(Ok(else_reject!(Some(req.headers.get($key))).to_str())));
            )*};
        }

        if req.method != http::Method::POST {
            reject!(METHOD_NOT_ALLOWED);
        }

        if req.uri != self.api_path {
            reject!(NOT_FOUND);
        }

        header! { bs
            service "x-dawnflame-service"
            method "x-dawnflame-method"
        }
        
        // TODO and other non-login services
        let auch = if !(service == "System.Register") {
            header! { s uid "x-dawnflame-uid"}
            header! { b _signature "x-dawnflame-signature" }

            let uid: Uid = else_reject!(Ok(uid.parse()));
            const BASE64_SIGNATURE_LENGTH: usize = 66; // data_encoding::BASE64.encode_len(SIGNATURE_LENGTH);
            let mut signature = [0; BASE64_SIGNATURE_LENGTH];
            if !matches!(data_encoding::BASE64.decode_mut(_signature.as_bytes(), &mut signature), Ok(SIGNATURE_LENGTH)) {
                reject!(BAD_REQUEST);
            }
            let signature = Signature::from_bytes(&signature[..SIGNATURE_LENGTH].try_into().unwrap());
            Some(RequestAuch { uid, signature })
        } else {
            None
        };

        log::info!("req {:x} gatewayed", req.id);
        Ok(Request { id: req.id, auch, service, method, payload: req.payload })
    }

    fn verify_auth(&self, req: &Request) -> Result<(), Response> {
        macro_rules! error {
            ($err:expr) => {
                return Err(Response { code: $err, data: None });
            };
        }

        macro_rules! else_error {
            ($ok_var:tt($val:expr), $err:expr) => {
                if let $ok_var(__v) = $val {
                    __v
                } else {
                    error!($err);
                }
            };
        }

        if let Some(RequestAuch { uid, signature }) = &req.auch {
            db_get!(self, tables::SESS_PKS, uid, sessions);
            let sessions = else_error!(Some(sessions), Code::NoAvailableSessions);
            let mut verified = None;
            for (pk, expires) in sessions.value() {
                if RawTime::from(std::time::SystemTime::now()).secs < expires {
                    let pk_unpacked = VerifyingKey::from_bytes(pk).expect("fatal: stored public key parse error");
                    if let Ok(()) = pk_unpacked.verify_strict(&req.payload, signature) {
                        verified = Some(pk);
                        break;
                    }
                }
            }
            let verified_pk = else_error!(Some(verified), Code::SessionVerifyFailed);
            self.db_first_insert(tables::REQ_WHICH_SESS, req.id, (*uid, verified_pk));
        }

        Ok(())
    }
}

// TODO all happy path

pub type TicketUid = u64;
pub type ForeignUid = u64;
pub type ForeignId = u16;
pub type VerifyCode = ByteString;
pub type RootKeyPdkSalt = [u8; 64];
pub type RegTime = TsSecs;
pub type SessPkExpires = TsSecs;

struct RegisterBeginReq {
    // ERR foreign may not exist
    foreign_id: ForeignId,
    // ERR uid may invaild
    // TODO not uid e.g. uname?
    may_foreign_uid: Option<ForeignUid>,
    // random-sk-in-local-storage normal BLAE session key
    // key may weak
    sess_pk: [u8; PUBLIC_KEY_LENGTH],
}

struct RegisterVerifierBeginReq {
    ticket_uid: TicketUid,
    foreign_id: ForeignId,
    may_foreign_uid: Option<ForeignUid>,
}

struct RegisterVerifierBeginRes {
    verify_code: VerifyCode,
}

// ERR verify may not available
struct RegisterBeginRes {
    verify_code: VerifyCode,
    ticket_uid: TicketUid,
}

struct RegisterVerifyReq {}

struct RegisterVerifierVerifyReq {
    ticket_uid: TicketUid,
}

// ERR verify may failed; port may be requested more times
// TODO store request times
struct RegisterVerifierVerifyRes {
    foreign_uid: ForeignUid,
}

struct RegisterVerifyRes {
    foreign_uid: ForeignUid,
    rootkey_salt: RootKeyPdkSalt,
}

struct RegisterFinishReq {
    // time when user hit the "register" button
    regtime: RegTime,
    // ERR key may weak
    // TODO what if key is "malformed" (not constructed by `KDF(regtime | pdksalt | password)`), e.g. random sk (edk in B(L)AE)?
    root_pk: [u8; PUBLIC_KEY_LENGTH],
}

struct RegisterFinishRes {
    uid: Uid,
}

enum RegisterState {
    Begined(RegisterStateBegined),
    Verified(RegisterStateVerified),
}

struct RegisterStateBegined {
    foreign_id: ForeignId,
    may_foreign_uid: Option<ForeignUid>,
}

struct RegisterStateVerified {
    foreign_id: ForeignId,
    foreign_uid: ForeignUid,
    rootkey_salt: RootKeyPdkSalt,
}

// TODO some challenge to get? e.g. sess_pk here
struct RegisterPrepareSessionReq {
    uid: Uid,
}

struct RegisterPrepareSessionRes {
    regtime: RegTime,
    rootkey_salt: RootKeyPdkSalt,
    // TODO sess_pk here to relate with creating like we did during reg? bloats complexity but signific safer
}

struct RegisterCreateSessionReq {
    uid: Uid,
    sess_pk: [u8; PUBLIC_KEY_LENGTH],
    rootkey_signature: [u8; SIGNATURE_LENGTH], /* sign(sess_pk) TODO time? */
}

struct RegisterCreateSessionRes {
    expires: SessPkExpires,
}

struct AccountRevokeSessionReq {
    uid: Uid,
    sess_pk: [u8; PUBLIC_KEY_LENGTH],
    rootkey_signature: [u8; SIGNATURE_LENGTH], /* sign(sess_pk) TODO time? */
}

struct AccountRevokeSessionRes {}

struct AccountInfoReq {}

struct AccountInfoRes {
    uid: Uid,
    // currect_sess_pk: [u8; PUBLIC_KEY_LENGTH], provide by front (?)
    foreigns: Vec<(ForeignId, ForeignUid)>,
    sess_pks: Vec<([u8; PUBLIC_KEY_LENGTH], SessPkExpires)>,
}

// for show interface only
trait RegisterVerifier {
    fn begin(&self, req: RegisterVerifierBeginReq) -> RegisterVerifierBeginRes;
    fn verify(&self, req: RegisterVerifierVerifyReq) -> RegisterVerifierVerifyRes;
}

impl GlobalContext {
    fn register_auch_set_sess(&self, ticket_uid: TicketUid, sess_pk: [u8; PUBLIC_KEY_LENGTH]) { todo!() }
    fn register_auch_get_sess(&self, ticket_uid: TicketUid) -> [u8; PUBLIC_KEY_LENGTH] { todo!() }
    fn register_auch_revoke_sess(&self, ticket_uid: TicketUid) { todo!() }

    fn register_begined(&self, ticket_uid: TicketUid, state: RegisterStateBegined) { todo!() }
    fn register_verify(&self, ticket_uid: TicketUid) -> RegisterStateBegined { todo!() } // ERR state enum not matched
    fn register_verified(&self, ticket_uid: TicketUid, state: RegisterStateVerified) { todo!() }
    fn register_finish(&self, ticket_uid: TicketUid) -> RegisterStateVerified { /* get and remove */ todo!() } // ERR state enum not matched

    fn create_user(&self, root_pk: [u8; PUBLIC_KEY_LENGTH], regtime: RegTime, rootkey_salt: RootKeyPdkSalt, foreign_id: ForeignId, foreign_uid: ForeignUid) -> Uid { todo!() }

    fn system_register_begin(&self, verifier: &impl RegisterVerifier, RegisterBeginReq { foreign_id, may_foreign_uid, sess_pk: session_pk }: RegisterBeginReq) -> RegisterBeginRes {
        let ticket_uid = TicketUid::from_be_bytes(cshake::rand::random_array());
        self.register_auch_set_sess(ticket_uid, session_pk);
        let RegisterVerifierBeginRes { verify_code } = verifier.begin(RegisterVerifierBeginReq { ticket_uid, foreign_id, may_foreign_uid: may_foreign_uid.clone() });
        self.register_begined(ticket_uid, RegisterStateBegined { foreign_id, may_foreign_uid });
        RegisterBeginRes { verify_code, ticket_uid }
    }
    
    fn system_register_verify(&self, verifier: &impl RegisterVerifier, ticket_uid: TicketUid, _: RegisterVerifyReq) -> RegisterVerifyRes {
        let RegisterStateBegined { foreign_id, may_foreign_uid } = self.register_verify(ticket_uid);
        let RegisterVerifierVerifyRes { foreign_uid } = verifier.verify(RegisterVerifierVerifyReq { ticket_uid });
        if let Some(n) = may_foreign_uid { assert_eq!(foreign_uid, n); }
        let rootkey_salt = cshake::rand::random_array(); // TODO more crypto safe?
        self.register_verified(ticket_uid, RegisterStateVerified { foreign_id, foreign_uid, rootkey_salt });
        RegisterVerifyRes { foreign_uid, rootkey_salt }
    }

    fn system_register_finish(&self, ticket_uid: TicketUid, RegisterFinishReq { regtime, root_pk }: RegisterFinishReq) -> RegisterFinishRes {
        let RegisterStateVerified { foreign_id, foreign_uid, rootkey_salt } = self.register_finish(ticket_uid);
        let uid = self.create_user(root_pk, regtime, rootkey_salt, foreign_id, foreign_uid);
        self.register_auch_revoke_sess(ticket_uid);
        RegisterFinishRes { uid }
    }

    fn system_register_prepare_session(&self, RegisterPrepareSessionReq { uid }: RegisterPrepareSessionReq) -> RegisterPrepareSessionRes { todo!() }
    fn system_register_create_session(&self, RegisterCreateSessionReq { uid, sess_pk, rootkey_signature }: RegisterCreateSessionReq) -> RegisterCreateSessionRes { todo!() }
    // fn system_account_info() {}
    fn system_account_revoke_session(&self, AccountRevokeSessionReq { uid, sess_pk, rootkey_signature }: AccountRevokeSessionReq) -> AccountRevokeSessionRes { todo!() }
}

fn make_resp<T: Serialize>(value: &T) -> http::Response<String> {
    http::Response::builder()
        .header(http::header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(serde_json::to_string(value).unwrap())
        .unwrap()
}

impl actor_core::Context for GlobalContext {
    type Req = RawRequest;
    type Res = http::Response<String>;
    type Err = actor_core::ClosedError;

    fn exec(&mut self, req: Self::Req) -> Result<Self::Res, Self::Err> {
        self.record_request(req.id, &req);
        Ok(match self.gateway(req) {
            Ok(req) => {
                if let Err(resp) = self.verify_auth(&req) {
                    make_resp(&resp)
                } else {
                    make_resp(&req)
                }
            },
            Err(resp) => resp.map(|_| String::new()),
        })
    }

    fn close(self) -> Result<(), Self::Err> {
        // TODO still need to repair when init
        log::info!("ctx closed");
        Ok(())
    }
}
