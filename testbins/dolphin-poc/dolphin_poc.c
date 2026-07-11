#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static HWND g_owner = 0;

static WCHAR ascii_lower(WCHAR value) {
    if (value >= L'A' && value <= L'Z') {
        return (WCHAR)(value - L'A' + L'a');
    }
    return value;
}

static BOOL running_in_dolphin(void) {
    static const WCHAR expected[] = L"dolphin.exe";
    WCHAR path[MAX_PATH] = {0};
    DWORD path_len = GetModuleFileNameW(0, path, MAX_PATH);
    DWORD expected_len = (DWORD)(sizeof(expected) / sizeof(expected[0]) - 1);
    if (path_len == 0 || path_len >= MAX_PATH || path_len < expected_len) {
        return FALSE;
    }
    for (DWORD i = 0; i < expected_len; ++i) {
        if (ascii_lower(path[path_len - expected_len + i]) != expected[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL CALLBACK find_owner_window(HWND window, LPARAM unused) {
    (void)unused;
    DWORD pid = 0;
    GetWindowThreadProcessId(window, &pid);
    if (pid == GetCurrentProcessId() && IsWindowVisible(window)) {
        g_owner = window;
        return FALSE;
    }
    return TRUE;
}

static void position_overlay(HWND window) {
    RECT rect = {0};
    if (!GetWindowRect(g_owner, &rect)) {
        return;
    }
    SetWindowPos(
        window,
        HWND_TOPMOST,
        rect.left + 24,
        rect.top + 48,
        300,
        76,
        SWP_NOACTIVATE | SWP_SHOWWINDOW
    );
}

static LRESULT CALLBACK overlay_window_proc(HWND window, UINT message, WPARAM wparam, LPARAM lparam) {
    (void)wparam;
    (void)lparam;
    switch (message) {
        case WM_PAINT: {
            PAINTSTRUCT paint = {0};
            HDC dc = BeginPaint(window, &paint);
            RECT rect = {0};
            GetClientRect(window, &rect);
            HBRUSH background = CreateSolidBrush(RGB(22, 31, 45));
            FillRect(dc, &rect, background);
            DeleteObject(background);
            SetBkMode(dc, TRANSPARENT);
            SetTextColor(dc, RGB(114, 217, 154));
            DrawTextW(
                dc,
                L"Decant UI PoC\nmanual-mapped into Dolphin",
                -1,
                &rect,
                DT_CENTER | DT_VCENTER | DT_WORDBREAK
            );
            EndPaint(window, &paint);
            return 0;
        }
        case WM_TIMER:
            position_overlay(window);
            return 0;
        case WM_LBUTTONDOWN:
        case WM_CLOSE:
            DestroyWindow(window);
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            return DefWindowProcW(window, message, wparam, lparam);
    }
}

static DWORD WINAPI show_poc_overlay(LPVOID unused) {
    (void)unused;
    if (!running_in_dolphin()) {
        return 0;
    }
    EnumWindows(find_owner_window, 0);
    if (g_owner == 0) {
        return 0;
    }

    WNDCLASSW window_class = {0};
    window_class.lpfnWndProc = overlay_window_proc;
    window_class.hInstance = GetModuleHandleW(0);
    window_class.hCursor = LoadCursorA(0, IDC_ARROW);
    window_class.lpszClassName = L"DecantDolphinPocOverlay";
    RegisterClassW(&window_class);

    HWND overlay = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
        window_class.lpszClassName,
        L"Decant UI PoC",
        WS_POPUP | WS_VISIBLE,
        0,
        0,
        300,
        76,
        g_owner,
        0,
        window_class.hInstance,
        0
    );
    if (overlay == 0) {
        return 0;
    }
    SetLayeredWindowAttributes(overlay, 0, 232, LWA_ALPHA);
    position_overlay(overlay);
    SetTimer(overlay, 1, 250, 0);

    MSG message = {0};
    while (GetMessageW(&message, 0, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH) {
        return TRUE;
    }

    DisableThreadLibraryCalls(instance);
    HANDLE worker = CreateThread(0, 0, show_poc_overlay, 0, 0, 0);
    if (worker != 0) {
        CloseHandle(worker);
    }
    return TRUE;
}
