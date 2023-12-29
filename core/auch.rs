use super::*;

impl GlobalContext {
    pub(crate) fn verify_auth(&self, req: &Request) -> Result<(), Response> {
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
            db_get!(self, db::tables::SESS_PKS, uid, sessions);
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
            self.db_first_insert(db::tables::REQ_WHICH_SESS, req.id, (*uid, verified_pk));
        }

        Ok(())
    }
}