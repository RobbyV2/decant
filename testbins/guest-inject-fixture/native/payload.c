#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

#include "probe.h"

#ifndef DECANT_PAYLOAD_TEXT
#define DECANT_PAYLOAD_TEXT "decant guest dll loaded"
#endif

#ifndef DECANT_PAYLOAD_IMPORT_STRESS
#define DECANT_PAYLOAD_IMPORT_STRESS 0
#endif

#ifndef DECANT_PAYLOAD_TLS_CALLBACK
#define DECANT_PAYLOAD_TLS_CALLBACK 0
#endif

#define DECANT_TLS_MARKER UINT64_C(0x715CDECAB10C600D)

static volatile uint64_t g_tls_marker = 0;

__declspec(dllexport) uint64_t decant_guest_inject_marker(void) {
    return DECANT_DLL_MARKER;
}

__declspec(dllexport) uintptr_t decant_guest_inject_reloc_anchor =
    (uintptr_t)&decant_guest_inject_marker;

#if DECANT_PAYLOAD_TLS_CALLBACK
static void NTAPI decant_guest_tls_callback(PVOID hinst, DWORD reason, PVOID reserved) {
    (void)hinst;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_tls_marker = DECANT_TLS_MARKER;
    }
}

__attribute__((used)) static PIMAGE_TLS_CALLBACK decant_guest_tls_callbacks[] = {
    decant_guest_tls_callback,
    0,
};

__attribute__((used, section(".rdata$T"))) const IMAGE_TLS_DIRECTORY64 _tls_used = {
    0,
    0,
    0,
    (ULONGLONG)decant_guest_tls_callbacks,
    0,
    0,
};
#endif

static int parse_hex64(const char *s, uint64_t *out) {
    uint64_t value = 0;
    for (int i = 0; i < 16; i++) {
        char c = s[i];
        uint8_t digit;
        if (c >= '0' && c <= '9') {
            digit = (uint8_t)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = (uint8_t)(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            digit = (uint8_t)(c - 'A' + 10);
        } else {
            return 0;
        }
        value = (value << 4) | digit;
    }
    *out = value;
    return 1;
}

static int has_magic(volatile decant_probe_t *probe) {
    const uint8_t expected[16] = DECANT_GUEST_MAGIC_BYTES;
    for (int i = 0; i < 16; i++) {
        if (probe->magic[i] != expected[i]) {
            return 0;
        }
    }
    return 1;
}

static void attach(void) {
    char env[32] = {0};
    DWORD n = GetEnvironmentVariableA("DECANT_GUEST_PROBE_ADDR", env, sizeof(env));
    if (n != 16) {
        return;
    }
    uint64_t addr = 0;
    if (!parse_hex64(env, &addr)) {
        return;
    }
    volatile decant_probe_t *probe = (volatile decant_probe_t *)(uintptr_t)addr;
    if (probe == 0 || !has_magic(probe)) {
        return;
    }
#if DECANT_PAYLOAD_TLS_CALLBACK
    if (g_tls_marker != DECANT_TLS_MARKER) {
        return;
    }
#endif
#if DECANT_PAYLOAD_IMPORT_STRESS
    LARGE_INTEGER counter = {0};
    QueryPerformanceCounter(&counter);
    uint64_t imported_mix =
        (uint64_t)GetCurrentProcessId() ^ GetTickCount64() ^ (uint64_t)counter.QuadPart;
    if (imported_mix == 0) {
        return;
    }
#endif
    probe->dll_marker = DECANT_DLL_MARKER;
    probe->dll_count++;
    probe->apc_result = DECANT_DLL_MARKER;
    probe->hijack_result = DECANT_DLL_MARKER;
    probe->remote_thread_result = DECANT_DLL_MARKER;
    probe->unload_marker = 0;
    probe->vad_probe = DECANT_DLL_MARKER;
    probe->tls_callback_fired = g_tls_marker;
    const char payload[] = DECANT_PAYLOAD_TEXT;
    for (int i = 0; i < 32; i++) {
        probe->payload[i] = i < (int)(sizeof(payload) - 1) ? (uint8_t)payload[i] : 0;
    }
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        attach();
    }
    return TRUE;
}
