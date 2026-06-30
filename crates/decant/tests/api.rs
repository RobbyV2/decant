use std::net::TcpListener;
use std::sync::Arc;
use std::thread;

use decant::prelude::*;
use decant_daemon::{Diag, serve};

fn demo_guest() -> MockGuest {
    MockGuest::builder()
        .process("target.exe", Pid(1234))
        .module("target.exe", 0x140000000, 0x1000)
        .region(0x150000, "rw-")
        .bytes_at(0x150100, b"\xDE\xCA\xFB\xAD")
        .u64_at(0x150200, 0x150240)
        .u32_at(0x150248, 1337)
        .done()
        .build()
}

#[test]
fn embedded_backend_scan_and_resolve() {
    let backend = MockBackend::new(demo_guest());
    let hits = scan(&backend, Pid(1234), &Pattern::parse("DE CA FB AD").unwrap()).unwrap();
    assert_eq!(hits, vec![0x150100]);
    let addr = resolve(&backend, Pid(1234), 0x150200, &[0x8]).unwrap();
    assert_eq!(addr, 0x150248);
    let v = backend.read(Pid(1234), addr, 4).unwrap();
    assert_eq!(u32::from_le_bytes(v.try_into().unwrap()), 1337);
}

#[test]
fn client_against_in_process_daemon() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let backend: Arc<dyn MemoryBackend> = Arc::new(MockBackend::new(demo_guest()));
    thread::spawn(move || {
        let _ = serve(listener, backend, Arc::new(Diag::new("mock")));
    });

    let mut client = Client::new(format!("127.0.0.1:{port}"));
    assert!(
        client
            .processes()
            .unwrap()
            .iter()
            .any(|p| p.name == "target.exe")
    );
    assert_eq!(
        client.read(Pid(1234), 0x150100, 4).unwrap(),
        b"\xDE\xCA\xFB\xAD"
    );
    client.write(Pid(1234), 0x150300, &[1, 2, 3, 4]).unwrap();
    assert_eq!(
        client.read(Pid(1234), 0x150300, 4).unwrap(),
        vec![1, 2, 3, 4]
    );
    assert_eq!(
        client.scan(Pid(1234), "DE CA FB AD").unwrap(),
        vec![0x150100]
    );
    assert_eq!(
        client.resolve(Pid(1234), 0x150200, &[0x8]).unwrap().0,
        0x150248
    );
}
