use decant_protocol::{
    read_msg, write_msg, Diagnostics, MemRegion, ModuleInfo, Pid, ProcessInfo, ProtoError, Request,
    Response,
};
use proptest::prelude::*;
use std::io::Cursor;

fn arb_pid() -> impl Strategy<Value = Pid> {
    any::<u32>().prop_map(Pid)
}

fn arb_process_info() -> impl Strategy<Value = ProcessInfo> {
    (arb_pid(), any::<String>()).prop_map(|(pid, name)| ProcessInfo { pid, name })
}

fn arb_module_info() -> impl Strategy<Value = ModuleInfo> {
    (any::<String>(), any::<u64>(), any::<u64>())
        .prop_map(|(name, base, size)| ModuleInfo { name, base, size })
}

fn arb_mem_region() -> impl Strategy<Value = MemRegion> {
    (any::<u64>(), any::<u64>(), any::<bool>(), any::<bool>(), any::<bool>()).prop_map(
        |(base, size, readable, writable, executable)| MemRegion {
            base,
            size,
            readable,
            writable,
            executable,
        },
    )
}

fn arb_diagnostics() -> impl Strategy<Value = Diagnostics> {
    (any::<String>(), any::<u64>(), any::<u64>(), any::<u64>()).prop_map(
        |(connector, reads, writes, unsupported_ops)| Diagnostics {
            connector,
            reads,
            writes,
            unsupported_ops,
        },
    )
}

fn arb_proto_error() -> impl Strategy<Value = ProtoError> {
    prop_oneof![
        (any::<Option<u32>>(), any::<Option<String>>())
            .prop_map(|(pid, name)| ProtoError::NoSuchProcess { pid, name }),
        (any::<u32>(), any::<String>())
            .prop_map(|(pid, module)| ProtoError::NoSuchModule { pid, module }),
        (any::<u64>(), any::<u64>(), any::<String>())
            .prop_map(|(addr, len, reason)| ProtoError::ReadFailed { addr, len, reason }),
        (any::<u64>(), any::<String>())
            .prop_map(|(addr, reason)| ProtoError::WriteFailed { addr, reason }),
        any::<String>().prop_map(|op| ProtoError::Unsupported { op }),
        any::<String>().prop_map(|message| ProtoError::Backend { message }),
    ]
}

fn arb_request() -> impl Strategy<Value = Request> {
    prop_oneof![
        Just(Request::Ping),
        Just(Request::ListProcesses),
        arb_pid().prop_map(Request::ProcessByPid),
        any::<String>().prop_map(Request::ProcessByName),
        arb_pid().prop_map(Request::ModuleList),
        (arb_pid(), any::<String>()).prop_map(|(p, s)| Request::ModuleByName(p, s)),
        (arb_pid(), any::<String>()).prop_map(|(p, s)| Request::ModuleExports(p, s)),
        (arb_pid(), any::<u64>(), any::<u64>())
            .prop_map(|(pid, addr, len)| Request::Read { pid, addr, len }),
        (arb_pid(), any::<u64>(), any::<Vec<u8>>())
            .prop_map(|(pid, addr, data)| Request::Write { pid, addr, data }),
        arb_pid().prop_map(Request::MemoryMap),
        Just(Request::Diagnostics),
    ]
}

fn arb_response() -> impl Strategy<Value = Response> {
    prop_oneof![
        Just(Response::Pong),
        prop::collection::vec(arb_process_info(), 0..8).prop_map(Response::Processes),
        arb_process_info().prop_map(Response::Process),
        prop::collection::vec(arb_module_info(), 0..8).prop_map(Response::Modules),
        arb_module_info().prop_map(Response::Module),
        prop::collection::vec((any::<String>(), any::<u64>()), 0..8).prop_map(Response::Exports),
        any::<Vec<u8>>().prop_map(Response::Data),
        any::<u64>().prop_map(Response::Written),
        prop::collection::vec(arb_mem_region(), 0..8).prop_map(Response::MemoryMap),
        arb_diagnostics().prop_map(Response::Diagnostics),
        arb_proto_error().prop_map(Response::Err),
    ]
}

proptest! {
    #[test]
    fn request_roundtrips(req in arb_request()) {
        let mut buf = Vec::new();
        write_msg(&mut buf, &req).unwrap();

        let mut cur = Cursor::new(&buf);
        let got: Request = read_msg(&mut cur).unwrap();
        prop_assert_eq!(&req, &got);

        let mut buf2 = Vec::new();
        write_msg(&mut buf2, &got).unwrap();
        prop_assert_eq!(&buf, &buf2);

        prop_assert_eq!(cur.position() as usize, cur.get_ref().len());
    }

    #[test]
    fn response_roundtrips(resp in arb_response()) {
        let mut buf = Vec::new();
        write_msg(&mut buf, &resp).unwrap();

        let mut cur = Cursor::new(&buf);
        let got: Response = read_msg(&mut cur).unwrap();
        prop_assert_eq!(&resp, &got);

        let mut buf2 = Vec::new();
        write_msg(&mut buf2, &got).unwrap();
        prop_assert_eq!(&buf, &buf2);
    }

    #[test]
    fn two_messages_read_back_in_order(a in arb_request(), b in arb_response()) {
        let mut buf = Vec::new();
        write_msg(&mut buf, &a).unwrap();
        write_msg(&mut buf, &b).unwrap();

        let mut cur = Cursor::new(&buf);
        let got_a: Request = read_msg(&mut cur).unwrap();
        let got_b: Response = read_msg(&mut cur).unwrap();
        prop_assert_eq!(a, got_a);
        prop_assert_eq!(b, got_b);
        prop_assert_eq!(cur.position() as usize, cur.get_ref().len());
    }

    #[test]
    fn random_bytes_never_panic(bytes in any::<Vec<u8>>()) {
        let mut cur = Cursor::new(&bytes);
        let _r: std::io::Result<Request> = read_msg(&mut cur);

        let mut cur = Cursor::new(&bytes);
        let _r: std::io::Result<Response> = read_msg(&mut cur);
    }

    #[test]
    fn framed_garbage_payload_never_panics(payload in prop::collection::vec(any::<u8>(), 0..512)) {
        let mut bytes = (payload.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(&payload);

        let mut cur = Cursor::new(&bytes);
        let _r: std::io::Result<Request> = read_msg(&mut cur);
        let mut cur = Cursor::new(&bytes);
        let _r: std::io::Result<Response> = read_msg(&mut cur);
    }
}
