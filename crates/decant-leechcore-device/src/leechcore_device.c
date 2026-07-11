/*
 * Minimal LeechCore device-plugin ABI adapter.
 *
 * LeechCore deliberately exposes LC_CONTEXT to device plugins. Keep these
 * declarations in lockstep with LC_CONTEXT_VERSION 0xc0e10004 (LeechCore
 * header 2.5). Only the stable prefix through the device callbacks is needed.
 */
#include <stddef.h>
#include <stdint.h>

#define DECANT_MAX_PATH 260
#define DECANT_PARAMETER_COUNT 16

typedef uint32_t DWORD;
typedef uint32_t BOOL;
typedef uint64_t QWORD;
typedef uint8_t BYTE;
typedef void *HANDLE;

typedef struct {
    DWORD dwVersion;
    DWORD _Reserved;
    QWORD qwFreq;
    struct {
        QWORD c;
        QWORD tm;
    } Call[8];
} DECANT_LC_STATISTICS;

typedef struct {
    DWORD dwVersion;
    DWORD dwPrintfVerbosity;
    char szDevice[DECANT_MAX_PATH];
    char szRemote[DECANT_MAX_PATH];
    int (*pfn_printf_opt)(const char *format, ...);
    QWORD paMax;
    BOOL fVolatile;
    BOOL fWritable;
    BOOL fRemote;
    BOOL fRemoteDisableCompress;
    char szDeviceName[DECANT_MAX_PATH];
} DECANT_LC_CONFIG;

typedef struct {
    char szName[DECANT_MAX_PATH];
    char szValue[DECANT_MAX_PATH];
    QWORD qwValue;
} DECANT_LC_DEVICE_PARAMETER;

typedef struct DECANT_LC_CONTEXT DECANT_LC_CONTEXT;

struct DECANT_LC_CONTEXT {
    DWORD version;
    DWORD dwHandleCount;
    HANDLE FLink;
    union {
        BYTE pad[48];
        QWORD align;
    } Lock;
    QWORD cReadScatterMEM;
    DECANT_LC_STATISTICS CallStat;
    HANDLE hDeviceModule;
    BOOL (*pfnCreate)(DECANT_LC_CONTEXT *ctx, void **error_info);
    DECANT_LC_CONFIG Config;
    DWORD cDeviceParameter;
    DECANT_LC_DEVICE_PARAMETER pDeviceParameter[DECANT_PARAMETER_COUNT];
    BOOL fWritable_deprecated;
    BOOL fPrintf[4];
    HANDLE hDevice;
    BOOL fMultiThread;
    void (*pfnReadScatter)(DECANT_LC_CONTEXT *ctx, DWORD count, void **mems);
    void (*pfnReadContiguous)(void *context);
    void (*pfnWriteScatter)(DECANT_LC_CONTEXT *ctx, DWORD count, void **mems);
    BOOL (*pfnWriteContiguous)(DECANT_LC_CONTEXT *ctx, QWORD address, DWORD length, BYTE *data);
    BOOL (*pfnGetOption)(DECANT_LC_CONTEXT *ctx, QWORD option, QWORD *value);
    BOOL (*pfnSetOption)(DECANT_LC_CONTEXT *ctx, QWORD option, QWORD value);
    BOOL (*pfnCommand)(DECANT_LC_CONTEXT *ctx, QWORD option, DWORD input_length,
                       BYTE *input, BYTE **output, DWORD *output_length);
    void (*pfnClose)(DECANT_LC_CONTEXT *ctx);
};

extern void *decant_device_open(const char *device, QWORD *max_address, BOOL *readonly);
extern void decant_device_close(void *device);
extern void decant_device_read_scatter(void *device, DWORD count, void **mems);
extern void decant_device_write_scatter(void *device, DWORD count, void **mems);

static void decant_read_scatter(DECANT_LC_CONTEXT *ctx, DWORD count, void **mems) {
    decant_device_read_scatter(ctx->hDevice, count, mems);
}

static void decant_write_scatter(DECANT_LC_CONTEXT *ctx, DWORD count, void **mems) {
    decant_device_write_scatter(ctx->hDevice, count, mems);
}

static void decant_close(DECANT_LC_CONTEXT *ctx) {
    void *device = ctx->hDevice;
    ctx->hDevice = NULL;
    if (device != NULL) {
        decant_device_close(device);
    }
}

BOOL decant_lc_install(DECANT_LC_CONTEXT *ctx, void **error_info) {
    QWORD max_address = 0;
    BOOL readonly = 1;
    void *device;

    if (error_info != NULL) {
        *error_info = NULL;
    }
    if (ctx == NULL || ctx->version != 0xc0e10004U) {
        return 0;
    }

    device = decant_device_open(ctx->Config.szDevice, &max_address, &readonly);
    if (device == NULL) {
        return 0;
    }
    if (max_address == 0) {
        decant_device_close(device);
        return 0;
    }

    ctx->hDevice = device;
    ctx->fMultiThread = 1;
    ctx->Config.paMax = max_address;
    ctx->Config.fVolatile = 1;
    ctx->Config.fWritable = readonly ? 0 : 1;
    ctx->pfnReadScatter = decant_read_scatter;
    ctx->pfnWriteScatter = readonly ? NULL : decant_write_scatter;
    ctx->pfnClose = decant_close;
    return 1;
}
