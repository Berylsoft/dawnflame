use super::*;

pub struct IncomingRequest {
    pub time: std::time::SystemTime,
    pub remote_addr: std::net::SocketAddr,
    pub header: http::request::Parts,
    pub payload: Bytes,
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

impl GlobalContext {
    pub(crate) fn gateway(&self, req: RawRequest) -> Result<Request, http::Response<()>> {
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
            service "x-empowerd-service"
            method "x-empowerd-method"
        }
        
        // TODO and other non-login services
        let auch = if !(service == "System.Register") {
            header! { s uid "x-empowerd-uid"}
            header! { b _signature "x-empowerd-signature" }

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
}
