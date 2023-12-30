use hyper::{server::conn::http1, service::service_fn, body::Incoming as IncomingBody, Request};

async fn _main() {
    pretty_env_logger::init();
    // TODO how axum with hyper1 do shutdown
    let (tx, rx) = async_channel::bounded::<()>(1);

    async_global_executor::spawn(async move {
        let ctx = actor::spawn(dawnflame::GlobalContext::init(dawnflame::GlobalConfig {
            root: &std::path::PathBuf::from(&"C:/swap/dftest"),
            db_mem_max: None,
            api_path: None,
        }));

        // TODO(async-net) AsyncToSocketAddrs
        let listener = async_net::TcpListener::bind(std::net::SocketAddr::from(([0, 0, 0, 0], 10027))).await.unwrap();
        loop {
            if !matches!(rx.try_recv(), Err(async_channel::TryRecvError::Empty)) {
                log::info!("close signal received");
                ctx.wait_close().await.unwrap();
                break;
            }
            let (stream, remote_addr) = listener.accept().await.unwrap();
            let io = smol_hyper::rt::FuturesIo::new(stream);
            let local_ref = ctx.clone();

            async_global_executor::spawn(async move {
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
            }).detach();
        }
    }).detach();

    async_ctrlc::CtrlC::new().unwrap().await;
    tx.send(()).await.unwrap();
    log::info!("close signal sent");
}

fn main() {
    async_global_executor::block_on(_main());
}
