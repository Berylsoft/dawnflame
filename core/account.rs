use super::*;

struct BeginReq {
    // ERR foreign may not exist
    foreign_id: ForeignId,
    // ERR uid may invaild
    // TODO not uid e.g. uname?
    may_foreign_uid: Option<ForeignUid>,
    // random-sk-in-local-storage normal BLAE session key
    // key may weak
    sess_pk: [u8; PUBLIC_KEY_LENGTH],
}

struct VerifierBeginReq {
    ticket_uid: TicketUid,
    foreign_id: ForeignId,
    may_foreign_uid: Option<ForeignUid>,
}

struct VerifierBeginRes {
    verify_code: VerifyCode,
}

// ERR verify may not available
struct BeginRes {
    verify_code: VerifyCode,
    ticket_uid: TicketUid,
}

struct VerifyReq {}

struct VerifierVerifyReq {
    ticket_uid: TicketUid,
}

// ERR verify may failed; port may be requested more times
// TODO store request times
struct VerifierVerifyRes {
    foreign_uid: ForeignUid,
}

struct VerifyRes {
    foreign_uid: ForeignUid,
    rootkey_salt: RootKeyPdkSalt,
}

struct FinishReq {
    // time when user hit the "register" button
    regtime: RegTime,
    // ERR key may weak
    // TODO what if key is "malformed" (not constructed by `KDF(regtime | pdksalt | password)`), e.g. random sk (edk in B(L)AE)?
    root_pk: [u8; PUBLIC_KEY_LENGTH],
}

struct FinishRes {
    uid: Uid,
}

enum State {
    Begined(StateBegined),
    Verified(StateVerified),
}

struct StateBegined {
    foreign_id: ForeignId,
    may_foreign_uid: Option<ForeignUid>,
}

struct StateVerified {
    foreign_id: ForeignId,
    foreign_uid: ForeignUid,
    rootkey_salt: RootKeyPdkSalt,
}

// TODO some challenge to get? e.g. sess_pk here
struct PrepareSessionReq {
    uid: Uid,
}

struct PrepareSessionRes {
    regtime: RegTime,
    rootkey_salt: RootKeyPdkSalt,
    // TODO sess_pk here to relate with creating like we did during reg? bloats complexity but signific safer
}

struct CreateSessionReq {
    uid: Uid,
    sess_pk: [u8; PUBLIC_KEY_LENGTH],
    rootkey_signature: [u8; SIGNATURE_LENGTH], /* sign(sess_pk) TODO time? */
}

struct CreateSessionRes {
    expires: SessPkExpires,
}

struct RevokeSessionReq {
    uid: Uid,
    sess_pk: [u8; PUBLIC_KEY_LENGTH],
    rootkey_signature: [u8; SIGNATURE_LENGTH], /* sign(sess_pk) TODO time? */
}

struct RevokeSessionRes {}

struct InfoReq {}

struct InfoRes {
    uid: Uid,
    // currect_sess_pk: [u8; PUBLIC_KEY_LENGTH], provide by front (?)
    foreigns: Vec<(ForeignId, ForeignUid)>,
    sess_pks: Vec<([u8; PUBLIC_KEY_LENGTH], SessPkExpires)>,
}

// for show interface only
trait Verifier {
    fn begin(&self, req: VerifierBeginReq) -> VerifierBeginRes;
    fn verify(&self, req: VerifierVerifyReq) -> VerifierVerifyRes;
}

impl GlobalContext {
    fn register_auch_set_sess(&self, ticket_uid: TicketUid, sess_pk: [u8; PUBLIC_KEY_LENGTH]) { todo!() }
    fn register_auch_get_sess(&self, ticket_uid: TicketUid) -> [u8; PUBLIC_KEY_LENGTH] { todo!() }
    fn register_auch_revoke_sess(&self, ticket_uid: TicketUid) { todo!() }

    fn register_begined(&self, ticket_uid: TicketUid, state: StateBegined) { todo!() }
    fn register_verify(&self, ticket_uid: TicketUid) -> StateBegined { todo!() } // ERR state enum not matched
    fn register_verified(&self, ticket_uid: TicketUid, state: StateVerified) { todo!() }
    fn register_finish(&self, ticket_uid: TicketUid) -> StateVerified { /* get and remove */ todo!() } // ERR state enum not matched

    fn create_user(&self, root_pk: [u8; PUBLIC_KEY_LENGTH], regtime: RegTime, rootkey_salt: RootKeyPdkSalt, foreign_id: ForeignId, foreign_uid: ForeignUid) -> Uid { todo!() }

    fn system_register_begin(&self, verifier: &impl Verifier, BeginReq { foreign_id, may_foreign_uid, sess_pk: session_pk }: BeginReq) -> BeginRes {
        let ticket_uid = TicketUid::from_be_bytes(cshake::rand::random_array());
        self.register_auch_set_sess(ticket_uid, session_pk);
        let VerifierBeginRes { verify_code } = verifier.begin(VerifierBeginReq { ticket_uid, foreign_id, may_foreign_uid: may_foreign_uid.clone() });
        self.register_begined(ticket_uid, StateBegined { foreign_id, may_foreign_uid });
        BeginRes { verify_code, ticket_uid }
    }
    
    fn system_register_verify(&self, verifier: &impl Verifier, ticket_uid: TicketUid, _: VerifyReq) -> VerifyRes {
        let StateBegined { foreign_id, may_foreign_uid } = self.register_verify(ticket_uid);
        let VerifierVerifyRes { foreign_uid } = verifier.verify(VerifierVerifyReq { ticket_uid });
        if let Some(n) = may_foreign_uid { assert_eq!(foreign_uid, n); }
        let rootkey_salt = cshake::rand::random_array(); // TODO more crypto safe?
        self.register_verified(ticket_uid, StateVerified { foreign_id, foreign_uid, rootkey_salt });
        VerifyRes { foreign_uid, rootkey_salt }
    }

    fn system_register_finish(&self, ticket_uid: TicketUid, FinishReq { regtime, root_pk }: FinishReq) -> FinishRes {
        let StateVerified { foreign_id, foreign_uid, rootkey_salt } = self.register_finish(ticket_uid);
        let uid = self.create_user(root_pk, regtime, rootkey_salt, foreign_id, foreign_uid);
        self.register_auch_revoke_sess(ticket_uid);
        FinishRes { uid }
    }

    fn system_register_prepare_session(&self, PrepareSessionReq { uid }: PrepareSessionReq) -> PrepareSessionRes { todo!() }
    fn system_register_create_session(&self, CreateSessionReq { uid, sess_pk, rootkey_signature }: CreateSessionReq) -> CreateSessionRes { todo!() }
    // fn system_account_info() {}
    fn system_account_revoke_session(&self, RevokeSessionReq { uid, sess_pk, rootkey_signature }: RevokeSessionReq) -> RevokeSessionRes { todo!() }
}
