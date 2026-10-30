#include "token.h"

BOOL IsProcessHighIntegrity() {
    HANDLE processToken = NULL;
    BOOL result = FALSE;
    PTOKEN_MANDATORY_LABEL tokenLabel = NULL;
    DWORD labelSize = 0;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &processToken)) {
        printf("[-] Error opening process token.\n");
        return FALSE;
    }

    if (!GetTokenInformation(processToken, TokenIntegrityLevel, NULL, 0, &labelSize)
        && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        tokenLabel = (PTOKEN_MANDATORY_LABEL)LocalAlloc(LPTR, labelSize);
    }

    if (!tokenLabel) {
        CloseHandle(processToken);
        return FALSE;
    }

    if (GetTokenInformation(processToken, TokenIntegrityLevel, tokenLabel, labelSize, &labelSize)) {
        DWORD il = *GetSidSubAuthority(tokenLabel->Label.Sid,
            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(tokenLabel->Label.Sid) - 1));
        result = (il >= SECURITY_MANDATORY_HIGH_RID);
    }

    LocalFree(tokenLabel);
    CloseHandle(processToken);
    return result;
}

BOOL SetDebugPrivilege() {
    HANDLE tokenHandle = NULL;
    TOKEN_PRIVILEGES privileges = { 0 };

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle)) {
        printf("[-] Failed to open process token (%lu)\n", GetLastError());
        return FALSE;
    }

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("[-] LookupPrivilegeValue failed (%lu)\n", GetLastError());
        CloseHandle(tokenHandle);
        return FALSE;
    }

    privileges.PrivilegeCount = 1;
    privileges.Privileges[0].Luid = luid;
    privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(tokenHandle, FALSE, &privileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("[-] AdjustTokenPrivileges failed (%lu)\n", GetLastError());
        CloseHandle(tokenHandle);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        printf("[-] SeDebugPrivilege not available\n");
        CloseHandle(tokenHandle);
        return FALSE;
    }

    CloseHandle(tokenHandle);
    return TRUE;
}
