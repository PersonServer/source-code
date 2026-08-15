//! The HTTP/1.1 accept loop. Kept out of `main.rs` so tests can run the real
//! server on an ephemeral port and drive it over a socket.

use std::future::Future;
use std::sync::Arc;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

use crate::app::App;
use crate::router;

/// Serve `app` on `listener` until `shutdown` resolves. In-flight connections
/// are dropped at shutdown; every request is short and idempotent to retry.
pub async fn run(listener: TcpListener, app: Arc<App>, shutdown: impl Future<Output = ()>) {
    tokio::pin!(shutdown);
    let mut housekeeping = tokio::time::interval(std::time::Duration::from_secs(600));
    housekeeping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (stream, _peer) = match accept {
                    Ok(pair) => pair,
                    Err(e) => { eprintln!("accept error: {e}"); continue; }
                };
                stream.set_nodelay(true).ok();
                let app = app.clone();
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req| {
                        let app = app.clone();
                        async move {
                            Ok::<_, std::convert::Infallible>(router::route(req, app).await)
                        }
                    });
                    let _ = http1::Builder::new().serve_connection(io, service).await;
                });
            }
            _ = housekeeping.tick() => {
                // Belt and braces: every purge here also happens inline on the
                // writes that matter, so correctness never depends on this
                // tick — it only keeps the tables tidy on a quiet server.
                let _ = app.store.purge_expired_sessions();
                let _ = app.store.purge_pending(86_400);
                let _ = app.store.purge_person_token_records();
            }
            _ = &mut shutdown => break,
        }
    }
}
