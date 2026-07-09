#pragma once

#include <stdint.h>

#define DECANT_GUEST_MAGIC_BYTES \
    {'D', 'E', 'C', 'A', 'N', 'T', ':', ':', 'G', 'U', 'E', 'S', 'T', 'I', 'N', 'J'}
#define DECANT_GUEST_FIXTURE_VERSION_BYTES \
    {'D', 'E', 'C', 'A', 'N', 'T', ':', ':', 'G', 'I', 'N', 'J', '0', '0', '0', '7'}
#define DECANT_GUEST_STUB_BYTES \
    {'D', 'E', 'C', 'A', 'N', 'T', ':', ':', 'S', 'T', 'U', 'B', '0', '0', '0', '4'}
#define DECANT_GUEST_RESULT_BYTES \
    {'D', 'E', 'C', 'A', 'N', 'T', ':', ':', 'R', 'E', 'S', 'U', 'L', 'T', '0', '4'}
#define DECANT_DLL_MARKER UINT64_C(0xD11DECA7600D5107)

typedef struct decant_probe {
    uint8_t magic[16];
    uint64_t tick;
    uint64_t dll_marker;
    uint64_t dll_count;
    uint8_t payload[32];
    uint64_t apc_result;
    uint64_t hijack_result;
    uint64_t remote_thread_result;
    uint64_t unload_marker;
    uint64_t vad_probe;
    uint64_t vtable[4];
    uint64_t tls_callback_fired;
} decant_probe_t;
