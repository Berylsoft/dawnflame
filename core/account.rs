use super::*;

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
