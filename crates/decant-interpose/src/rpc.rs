use std::sync::Mutex;

use decant_client::Client;
use decant_protocol::{Request, Response};

static CLIENT: Mutex<Option<Client>> = Mutex::new(None);

pub fn request(req: Request) -> Option<Response> {
    let mut guard = CLIENT.lock().ok()?;
    if guard.is_none() {
        *guard = Some(Client::from_env());
    }
    guard.as_mut()?.send(req).ok()
}
