#pragma once

#include <stdint.h>

#define DECANT_GUEST_MAGIC_BYTES \
    {'D', 'E', 'C', 'A', 'N', 'T', ':', ':', 'G', 'U', 'E', 'S', 'T', 'I', 'N', 'J'}
#define DECANT_GUEST_FIXTURE_VERSION_BYTES \
    {'D', 'E', 'C', 'A', 'N', 'T', ':', ':', 'G', 'I', 'N', 'J', '0', '0', '0', '8'}
#define DECANT_GUEST_STUB_BYTES \
    {'D', 'E', 'C', 'A', 'N', 'T', ':', ':', 'S', 'T', 'U', 'B', '0', '0', '0', '4'}
#define DECANT_GUEST_RESULT_BYTES \
    {'D', 'E', 'C', 'A', 'N', 'T', ':', ':', 'R', 'E', 'S', 'U', 'L', 'T', '0', '4'}
#define DECANT_DLL_MARKER UINT64_C(0xD11DECA7600D5107)
#define DECANT_GUEST_DIAGNOSTIC_BYTES \
    {'D', 'E', 'C', 'A', 'N', 'T', ':', ':', 'D', 'I', 'A', 'G', '0', '0', '0', '1'}

#define DECANT_GUEST_DIAGNOSTIC_PING UINT64_C(1)
#define DECANT_GUEST_DIAGNOSTIC_FILE_IO UINT64_C(2)
#define DECANT_GUEST_DIAGNOSTIC_STATUS_IDLE UINT64_C(0)
#define DECANT_GUEST_DIAGNOSTIC_STATUS_BUSY UINT64_C(1)
#define DECANT_GUEST_DIAGNOSTIC_STATUS_OK UINT64_C(2)
#define DECANT_GUEST_DIAGNOSTIC_STATUS_BAD_REQUEST UINT64_C(3)
#define DECANT_GUEST_DIAGNOSTIC_STATUS_FAILED UINT64_C(4)

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

typedef struct decant_diagnostic_mailbox {
    uint8_t magic[16];
    uint64_t request;
    uint64_t request_id;
    uint64_t completed_id;
    uint64_t status;
    uint64_t tick;
    uint8_t payload[64];
} decant_diagnostic_mailbox_t;
