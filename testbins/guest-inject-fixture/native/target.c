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

__attribute__((used)) static volatile decant_probe_t g_probe = {
    .magic = DECANT_GUEST_MAGIC_BYTES,
    .tick = 0,
    .dll_marker = 0,
    .dll_count = 0,
    .payload = {0},
};

__attribute__((used)) static volatile uint8_t g_fixture_version[16] =
    DECANT_GUEST_FIXTURE_VERSION_BYTES;

__attribute__((used)) static volatile uint8_t g_iat_result[16] =
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
    write_hex_line("  tick          : ", g_probe.tick);
    write_hex_line("  dll_marker    : ", g_probe.dll_marker);
    write_hex_line("  dll_count     : ", g_probe.dll_count);
    write_hex_line("  expected mark : ", DECANT_DLL_MARKER);
    write_all("  magic AOB     : 44 45 43 41 4E 54 3A 3A 47 55 45 53 54 49 4E 4A\r\n");
    write_all("  fixture AOB   : 44 45 43 41 4E 54 3A 3A 47 49 4E 4A 30 30 30 35\r\n");
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
    print_status();
    for (;;) {
        g_probe.tick++;
        if (g_probe.dll_marker == DECANT_DLL_MARKER && !observed) {
            observed = 1;
            write_all("guest-inject-target: dll marker observed\r\n");
        }
        sleep_ms(1000);
    }
}

static void resident_cached_sleep(void) {
    int observed = 0;
    g_cached_sleep = Sleep;
    print_status();
    write_all("guest-inject-target: cached Sleep pointer\r\n");
    for (;;) {
        sleep_fn_t fn = g_cached_sleep;
        g_probe.tick++;
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
