#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

#include "probe.h"

__asm__(
    ".section .text$decant,\"x\"\n"
    ".balign 16\n"
    ".globl decant_guest_inject_stage\n"
    "decant_guest_inject_stage:\n"
    ".ascii \"DECANT::STUB0004\"\n"
    ".rept 131056\n"
    "nop\n"
    ".endr\n"
    "ret\n"
    ".text\n");

extern uint8_t decant_guest_inject_stage;
typedef void(WINAPI *sleep_fn_t)(DWORD);

static volatile sleep_fn_t g_cached_sleep = 0;
static HANDLE g_hijack_worker_event = 0;
static volatile DWORD g_hijack_worker_tid = 0;

__attribute__((used)) static volatile decant_probe_t g_probe = {
    .magic = DECANT_GUEST_MAGIC_BYTES,
    .tick = 0,
    .dll_marker = 0,
    .dll_count = 0,
    .payload = {0},
    .apc_result = 0,
    .hijack_result = 0,
    .remote_thread_result = 0,
    .unload_marker = 0,
    .vad_probe = 0,
    .vtable = {0, 0, 0, 0},
    .tls_callback_fired = 0,
};

__attribute__((used)) static volatile decant_diagnostic_mailbox_t g_diagnostics = {
    .magic = DECANT_GUEST_DIAGNOSTIC_BYTES,
    .request = 0,
    .request_id = 0,
    .completed_id = 0,
    .status = DECANT_GUEST_DIAGNOSTIC_STATUS_IDLE,
    .tick = 0,
    .payload = {0},
};

__attribute__((used)) static volatile uint8_t g_fixture_version[16] =
    DECANT_GUEST_FIXTURE_VERSION_BYTES;

__attribute__((used)) static volatile uint8_t g_iat_result[24] =
    DECANT_GUEST_RESULT_BYTES;

static DWORD c_len(const char *s) {
    DWORD n = 0;
    while (s[n] != 0) {
        n++;
    }
    return n;
}

static void write_all(const char *s) {
    DWORD written = 0;
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    WriteFile(out, s, c_len(s), &written, 0);
}

static char hex_digit(uint8_t v) {
    return (char)(v < 10 ? ('0' + v) : ('A' + (v - 10)));
}

static void hex64(uint64_t value, char out[17]) {
    for (int i = 0; i < 16; i++) {
        uint8_t shift = (uint8_t)((15 - i) * 4);
        out[i] = hex_digit((uint8_t)((value >> shift) & 0xF));
    }
    out[16] = 0;
}

static void write_hex_line(const char *label, uint64_t value) {
    char hex[17];
    hex64(value, hex);
    write_all(label);
    write_all("0x");
    write_all(hex);
    write_all("\r\n");
}

static void diagnostic_payload(const char *text) {
    for (DWORD i = 0; i < sizeof(g_diagnostics.payload); i++) {
        char c = text[i];
        g_diagnostics.payload[i] = (uint8_t)c;
        if (c == 0) {
            return;
        }
    }
    g_diagnostics.payload[sizeof(g_diagnostics.payload) - 1] = 0;
}

static int diagnostic_file_io_roundtrip(void) {
    static const char file_name[] = "decant-guest-diagnostics.txt";
    static const char contents[] = "DECANT guest diagnostics file round-trip\r\n";
    char path[MAX_PATH] = {0};
    DWORD path_len = GetTempPathA((DWORD)sizeof(path), path);
    if (path_len == 0 || path_len >= sizeof(path)) {
        return 0;
    }
    for (DWORD i = 0; i < sizeof(file_name); i++) {
        if (path_len + i >= sizeof(path)) {
            return 0;
        }
        path[path_len + i] = file_name[i];
    }

    HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }
    DWORD written = 0;
    BOOL wrote = WriteFile(file, contents, sizeof(contents) - 1, &written, 0);
    CloseHandle(file);
    if (!wrote || written != sizeof(contents) - 1) {
        return 0;
    }

    file = CreateFileA(
        path,
        GENERIC_READ,
        FILE_SHARE_READ,
        0,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        0
    );
    if (file == INVALID_HANDLE_VALUE) {
        return 0;
    }
    char readback[sizeof(contents)] = {0};
    DWORD read = 0;
    BOOL read_ok = ReadFile(file, readback, sizeof(contents) - 1, &read, 0);
    CloseHandle(file);
    if (!read_ok || read != sizeof(contents) - 1) {
        return 0;
    }
    for (DWORD i = 0; i < sizeof(contents) - 1; i++) {
        if (readback[i] != contents[i]) {
            return 0;
        }
    }
    return 1;
}

static void service_diagnostics(void) {
    uint64_t request_id = g_diagnostics.request_id;
    if (request_id == 0 || request_id == g_diagnostics.completed_id) {
        return;
    }

    g_diagnostics.status = DECANT_GUEST_DIAGNOSTIC_STATUS_BUSY;
    switch (g_diagnostics.request) {
    case DECANT_GUEST_DIAGNOSTIC_PING:
        diagnostic_payload("fixture diagnostic ping ok");
        g_diagnostics.status = DECANT_GUEST_DIAGNOSTIC_STATUS_OK;
        break;
    case DECANT_GUEST_DIAGNOSTIC_FILE_IO:
        if (diagnostic_file_io_roundtrip()) {
            diagnostic_payload("fixture diagnostic file io ok");
            g_diagnostics.status = DECANT_GUEST_DIAGNOSTIC_STATUS_OK;
        } else {
            diagnostic_payload("fixture diagnostic file io failed");
            g_diagnostics.status = DECANT_GUEST_DIAGNOSTIC_STATUS_FAILED;
        }
        break;
    default:
        diagnostic_payload("fixture diagnostic unsupported request");
        g_diagnostics.status = DECANT_GUEST_DIAGNOSTIC_STATUS_BAD_REQUEST;
        break;
    }
    g_diagnostics.tick++;
    g_diagnostics.completed_id = request_id;
}

static DWORD WINAPI hijack_worker(LPVOID param) {
    HANDLE event = (HANDLE)param;
    for (;;) {
        // An alertable wait gives the APC fixture a deterministic target thread. The same
        // worker remains safe for the thread-hijack fixture path.
        WaitForSingleObjectEx(event, 1000, TRUE);
    }
    return 0;
}

static void start_hijack_worker(void) {
    if (g_hijack_worker_tid != 0) {
        return;
    }
    g_hijack_worker_event = CreateEventA(0, TRUE, FALSE, 0);
    if (g_hijack_worker_event == 0) {
        write_all("guest-inject-target: CreateEventA for hijack worker failed\r\n");
        return;
    }
    DWORD tid = 0;
    HANDLE thread = CreateThread(0, 0, hijack_worker, g_hijack_worker_event, 0, &tid);
    if (thread == 0) {
        write_all("guest-inject-target: CreateThread for hijack worker failed\r\n");
        CloseHandle(g_hijack_worker_event);
        g_hijack_worker_event = 0;
        return;
    }
    g_hijack_worker_tid = tid;
    CloseHandle(thread);
}

__attribute__((noinline)) static void sleep_ms(DWORD milliseconds) {
    Sleep(milliseconds);
}

static int contains(const char *haystack, const char *needle) {
    if (*needle == 0) {
        return 1;
    }
    for (const char *h = haystack; *h != 0; h++) {
        const char *a = h;
        const char *b = needle;
        while (*a != 0 && *b != 0 && *a == *b) {
            a++;
            b++;
        }
        if (*b == 0) {
            return 1;
        }
    }
    return 0;
}

static void publish_probe_env(void) {
    char hex[17];
    hex64((uint64_t)(uintptr_t)&g_probe, hex);
    SetEnvironmentVariableA("DECANT_GUEST_PROBE_ADDR", hex);
}

static void print_status(void) {
    write_all("guest-inject-target: ready\r\n");
    write_hex_line("  probe @       : ", (uint64_t)(uintptr_t)&g_probe);
    write_hex_line("  dll_marker @  : ", (uint64_t)(uintptr_t)&g_probe.dll_marker);
    write_hex_line("  stub @        : ", (uint64_t)(uintptr_t)&decant_guest_inject_stage);
    write_hex_line("  result @      : ", (uint64_t)(uintptr_t)&g_iat_result);
    write_hex_line("  diagnostics @ : ", (uint64_t)(uintptr_t)&g_diagnostics);
    write_hex_line("  apc_result @  : ", (uint64_t)(uintptr_t)&g_probe.apc_result);
    write_hex_line("  hijack_result @: ", (uint64_t)(uintptr_t)&g_probe.hijack_result);
    write_hex_line("  rt_result @   : ", (uint64_t)(uintptr_t)&g_probe.remote_thread_result);
    write_hex_line("  unload_marker @: ", (uint64_t)(uintptr_t)&g_probe.unload_marker);
    write_hex_line("  vad_probe @   : ", (uint64_t)(uintptr_t)&g_probe.vad_probe);
    write_hex_line("  vtable @      : ", (uint64_t)(uintptr_t)&g_probe.vtable);
    write_hex_line("  tls_cb @      : ", (uint64_t)(uintptr_t)&g_probe.tls_callback_fired);
    write_hex_line("  hijack_tid    : ", (uint64_t)g_hijack_worker_tid);
    write_hex_line("  tick          : ", g_probe.tick);
    write_hex_line("  dll_marker    : ", g_probe.dll_marker);
    write_hex_line("  dll_count     : ", g_probe.dll_count);
    write_hex_line("  expected mark : ", DECANT_DLL_MARKER);
    write_all("  magic AOB     : 44 45 43 41 4E 54 3A 3A 47 55 45 53 54 49 4E 4A\r\n");
    write_all("  fixture AOB   : 44 45 43 41 4E 54 3A 3A 47 49 4E 4A 30 30 30 38\r\n");
    write_all("  stub AOB      : 44 45 43 41 4E 54 3A 3A 53 54 55 42 30 30 30 34\r\n");
    write_all("  result AOB    : 44 45 43 41 4E 54 3A 3A 52 45 53 55 4C 54 30 34\r\n");
}

static UINT self_load(void) {
    HMODULE dll = LoadLibraryA("guest_inject_probe.dll");
    if (dll == 0) {
        write_all("guest-inject-target: LoadLibraryA(guest_inject_probe.dll) failed\r\n");
        return 3;
    }
    for (int i = 0; i < 50; i++) {
        if (g_probe.dll_marker == DECANT_DLL_MARKER) {
            write_all("guest-inject-target: self-load PASS\r\n");
            print_status();
            return 0;
        }
        sleep_ms(100);
    }
    write_all("guest-inject-target: self-load timed out\r\n");
    return 4;
}

static void resident(void) {
    int observed = 0;
    start_hijack_worker();
    print_status();
    for (;;) {
        g_probe.tick++;
        service_diagnostics();
        if (g_probe.dll_marker == DECANT_DLL_MARKER && !observed) {
            observed = 1;
            write_all("guest-inject-target: dll marker observed\r\n");
        }
        sleep_ms(1000);
    }
}

static void resident_cached_sleep(void) {
    int observed = 0;
    start_hijack_worker();
    g_cached_sleep = Sleep;
    print_status();
    write_all("guest-inject-target: cached Sleep pointer\r\n");
    for (;;) {
        sleep_fn_t fn = g_cached_sleep;
        g_probe.tick++;
        service_diagnostics();
        if (g_probe.dll_marker == DECANT_DLL_MARKER && !observed) {
            observed = 1;
            write_all("guest-inject-target: dll marker observed\r\n");
        }
        fn(1000);
    }
}

void mainCRTStartup(void) {
    publish_probe_env();
    const char *cmd = GetCommandLineA();
    if (contains(cmd, "--self-load")) {
        ExitProcess(self_load());
    }
    if (contains(cmd, "--once")) {
        print_status();
        ExitProcess(0);
    }
    if (contains(cmd, "--cached-sleep")) {
        resident_cached_sleep();
    }
    resident();
}
