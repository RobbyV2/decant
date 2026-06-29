use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

use decant_protocol::{read_msg, write_msg, Request, Response};

static CONN: Mutex<Option<TcpStream>> = Mutex::new(None);

fn endpoint() -> String {
    std::env::var("DECANT_ENDPOINT").unwrap_or_else(|_| "127.0.0.1:7878".to_string())
}

pub fn request(req: Request) -> Option<Response> {
    let mut guard = CONN.lock().ok()?;

    for _ in 0..2 {
        if guard.is_none() {
            match TcpStream::connect(endpoint()) {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
                    *guard = Some(stream);
                }
                Err(_) => return None,
            }
        }

        let outcome = {
            let stream = match guard.as_mut() {
                Some(s) => s,
                None => return None,
            };
            write_msg(stream, &req).and_then(|()| read_msg::<_, Response>(stream))
        };

        match outcome {
            Ok(resp) => return Some(resp),
            Err(_) => {
                *guard = None;
            }
        }
    }

    None
}
