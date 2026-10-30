#include "enumproc.h"
#include "convert.h"

static void PrintProcInfo(const char* processName, DWORD pid, const char* fullPath) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    WORD saved = consoleInfo.wAttributes;

    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("  %-30s PID: %-10lu %s\n", processName, pid, fullPath);
    SetConsoleTextAttribute(hConsole, saved);
}

BOOL enumSec(const char* edrProcesses[], size_t count) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed CreateToolhelp32Snapshot\n");
        return FALSE;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    BOOL found = FALSE;

    if (Process32First(hSnapshot, &pe32)) {
        do {
            char* exeName = WideCharToChar(pe32.szExeFile);
            if (!exeName) continue;

            for (size_t i = 0; i < count; ++i) {
                if (_stricmp(exeName, edrProcesses[i]) == 0) {
                    found = TRUE;
                    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
                    if (hProc) {
                        CHAR fullPath[MAX_PATH] = { 0 };
                        DWORD size = MAX_PATH;
                        QueryFullProcessImageNameA(hProc, 0, fullPath, &size);
                        PrintProcInfo(exeName, pe32.th32ProcessID, fullPath);
                        CloseHandle(hProc);
                    } else {
                        PrintProcInfo(exeName, pe32.th32ProcessID, "(access denied)");
                    }
                    break;
                }
            }
            free(exeName);
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    if (!found)
        printf("  (none detected)\n");

    return TRUE;
}

BOOL listProc() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[-] Failed CreateToolhelp32Snapshot\n");
        return FALSE;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            char* exeName = WideCharToChar(pe32.szExeFile);
            if (!exeName) continue;

            CHAR fullPath[MAX_PATH] = { 0 };
            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProc) {
                DWORD size = MAX_PATH;
                QueryFullProcessImageNameA(hProc, 0, fullPath, &size);
                CloseHandle(hProc);
            }

            printf("  %-40s PID: %-10lu %s\n", exeName, pe32.th32ProcessID,
                   fullPath[0] ? fullPath : "(access denied)");

            free(exeName);
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return TRUE;
}
