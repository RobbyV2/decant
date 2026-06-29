//! # rpc — the carafe's daemon client ("the funnel", carafe side)
//!
//! A thin, **panic-free** client that frames [`decant_protocol`] requests over a
//! cached localhost `TcpStream` to the cellar daemon. Under Wine the stream is a
//! Winsock socket and `127.0.0.1` is the host loopback (ADR-0002), so the
//! Wine-hosted tool's intercepted calls reach the daemon running natively on the
//! VM host.
//!
//! ## Contract
//!
//! [`request`] returns `Some(Response)` on a completed round-trip and `None` on any
//! failure (no daemon, write error, malformed reply). A dead daemon must never
//! crash the host tool — every error path here is a `None`, never a panic, never an
//! `unwrap` on external state. The connection is cached behind a `Mutex` and
//! transparently reconnected once on error.
//!
//! Pure `std::net`, so it builds and is reasoned about identically on the host and
//! on `x86_64-pc-windows-gnu`.

use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use decant_protocol::{read_msg, write_msg, Request, Response};

/// Cached connection to the daemon. `None` means "not connected" (first use, or
/// dropped after an error so the next call reconnects).
static CONN: Mutex<Option<TcpStream>> = Mutex::new(None);

/// The daemon address: `DECANT_ENDPOINT` or the documented default `127.0.0.1:7878`.
fn endpoint() -> String {
    std::env::var("DECANT_ENDPOINT").unwrap_or_else(|_| "127.0.0.1:7878".to_string())
}

/// Send `req` and return the daemon's [`Response`], or `None` on any failure.
///
/// Reconnects once if the cached stream is absent or errors mid-exchange, so a
/// daemon restart between calls is recovered transparently. Read/write timeouts
/// bound a hung daemon so the host tool cannot wedge forever.
pub fn request(req: Request) -> Option<Response> {
    let mut guard = CONN.lock().ok()?;

    // At most two attempts: reuse the cached stream, and on error drop it and make
    // one fresh connection.
    for _ in 0..2 {
        if guard.is_none() {
            match TcpStream::connect(endpoint()) {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                    *guard = Some(stream);
                }
                Err(_) => return None, // daemon unreachable — fail, don't panic.
            }
        }

        let outcome = {
            // Safe: we just ensured `Some` above (or looped back to reconnect).
            let stream = match guard.as_mut() {
                Some(s) => s,
                None => return None,
            };
            write_msg(stream, &req).and_then(|()| read_msg::<_, Response>(stream))
        };

        match outcome {
            Ok(resp) => return Some(resp),
            Err(_) => {
                // Drop the broken stream and retry once with a fresh connection.
                *guard = None;
            }
        }
    }

    None
}
