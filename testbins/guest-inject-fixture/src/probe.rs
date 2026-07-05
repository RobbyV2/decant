pub const MAGIC: [u8; 16] = *b"DECANT::GUESTINJ";
pub const DLL_MARKER: u64 = 0xD11D_ECA7_600D_5107;
#[allow(dead_code)]
pub const PAYLOAD: &[u8] = b"decant guest dll loaded";

#[repr(C)]
pub struct Probe {
    pub magic: [u8; 16],
    pub tick: u64,
    pub dll_marker: u64,
    pub dll_count: u64,
    pub payload: [u8; 32],
}

impl Probe {
    #[allow(dead_code)]
    pub const fn new() -> Self {
        Self {
            magic: MAGIC,
            tick: 0,
            dll_marker: 0,
            dll_count: 0,
            payload: [0; 32],
        }
    }
}
