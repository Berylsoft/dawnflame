use hyper::{server::conn::http1, service::service_fn, body::Incoming as IncomingBody, Request};

#[tokio::main]
async fn main() {
    pretty_env_logger::init();
    let (tx, mut rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let ctx = tokio_actor::spawn(dawnflame::GlobalContext::init(dawnflame::GlobalConfig {
            root: &std::path::PathBuf::from(&"C:/swap/dftest"),
            db_mem_max: None,
            api_path: None,
        }));

        let listener = tokio::net::TcpListener::bind(("0.0.0.0", 10027)).await.unwrap();
        loop {
            if let Ok(()) | Err(tokio::sync::oneshot::error::TryRecvError::Closed) = rx.try_recv() {
                log::info!("close signal received");
                ctx.wait_close().await.unwrap();
                break;
            }
            let (stream, remote_addr) = listener.accept().await.unwrap();
            let io = hyper_util::rt::TokioIo::new(stream);
            let local_ref = ctx.clone();

            tokio::task::spawn(async move {
                let service = service_fn(move |req: Request<IncomingBody>| {
                    let local_ref = local_ref.clone();
                    async move {
                        let (header, payload) = req.into_parts();
                        Ok::<_, core::convert::Infallible>(local_ref.request(dawnflame::IncomingRequest {
                            time: std::time::SystemTime::now(),
                            remote_addr,
                            header,
                            payload: http_body_util::BodyExt::collect(payload).await.unwrap().to_bytes(),
                        }.into()).await.unwrap())
                    }
                });
                http1::Builder::new().serve_connection(io, service).await.unwrap()
            });
        }
    });

    tokio::signal::ctrl_c().await.unwrap();
    tx.send(()).unwrap();
}
