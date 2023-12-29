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

// pub struct Session<'a> {
//     pk: &'a [u8; PUBLIC_KEY_LENGTH],
//     expire: TsSecs,
// }

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
pub struct RequestAuch {
    // TODO rootkey salt rather than uid?
    pub uid: Uid,
    // TODO unify [u8; LEN] and Signature/VerifyingKey
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

impl GlobalContext {
    pub fn init(GlobalConfig { root, db_mem_max, api_path }: GlobalConfig) -> Self {
        let db_mem_max = db_mem_max.unwrap_or(256 * 2usize.pow(20) /* 256MiB */);
        let api_path = api_path.unwrap_or("/__dawnflame_api");

        let db = Self::db_init(root.join("main-db"), db_mem_max);

        let event_path = root.join("events");
        // std::fs::create_dir_all(&event_path).unwrap();

        Self { db, event_path, api_path }
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

mod raw;
mod auch;
mod db;
mod account;

use raw::RawRequest;
pub use raw::IncomingRequest;
