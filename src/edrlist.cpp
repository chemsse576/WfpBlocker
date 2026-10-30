#include "edrlist.h"

const char* edrNames[] = {
    // Microsoft Defender / MDE
    "MsMpEng.exe",
    "MsSense.exe",
    "SenseIR.exe",
    "SenseNdr.exe",
    "SenseTVM.exe",
    "SenseCncProxy.exe",
    "smartscreen.exe",
    "NisSrv.exe",
    "SecurityHealthService.exe",
    "SecurityHealthSystray.exe",

    // CrowdStrike Falcon
    "CSFalconService.exe",
    "CSFalconContainer.exe",
    "csagent.exe",
    "falconhost.exe",

    // SentinelOne
    "SentinelAgent.exe",
    "SentinelServiceHost.exe",
    "SentinelStaticEngine.exe",
    "SentinelStaticEngineScanner.exe",
    "SentinelHelperService.exe",
    "LogProcessorService.exe",

    // Carbon Black (VMware / Broadcom)
    "cb.exe",
    "RepMgr.exe",
    "RepUtils.exe",
    "RepWSC.exe",
    "CbDefense.exe",
    "CbDefenseService.exe",

    // Palo Alto Cortex XDR
    "CortexXDR.exe",
    "cyserver.exe",
    "CyveraService.exe",
    "CyveraConsole.exe",
    "Traps.exe",
    "cytray.exe",

    // Elastic EDR
    "winlogbeat.exe",
    "elastic-agent.exe",
    "elastic-endpoint.exe",
    "filebeat.exe",

    // Symantec / Broadcom SEP
    "ccSvcHst.exe",
    "rtvscan.exe",
    "SMC.exe",
    "SymCorpUI.exe",
    "SepMasterService.exe",

    // Cylance (BlackBerry)
    "CylanceSvc.exe",
    "CylanceUI.exe",

    // Trend Micro
    "Ntrtscan.exe",
    "TmListen.exe",
    "TmCCSF.exe",
    "COREAGENT.exe",
    "ds_monitor.exe",

    // ESET
    "ekrn.exe",
    "egui.exe",
    "ERAAgent.exe",

    // Sophos
    "SophosCleanup.exe",
    "SophosHealth.exe",
    "SophosUI.exe",
    "SophosAgent.exe",
    "SophosFileScanner.exe",
    "SSPService.exe",

    // Bitdefender
    "bdagent.exe",
    "bdntwrk.exe",
    "bdservicehost.exe",
    "EPSecurityService.exe",
    "EPProtectedService.exe",

    // Kaspersky
    "avp.exe",
    "avpui.exe",
    "klnagent.exe",

    // McAfee / Trellix
    "mfemms.exe",
    "mfevtps.exe",
    "McTray.exe",
    "masvc.exe",
    "macmnsvc.exe",
    "mfetp.exe",

    // FireEye / Trellix / Mandiant
    "xagt.exe",
    "HipMgmt.exe",
    "firetray.exe",

    // Fortinet
    "FortiESNAC.exe",
    "FortiTray.exe",
    "FCDBLog.exe",
    "fortiwad.exe",

    // Cybereason
    "CybereasonSensor.exe",
    "CybereasonRansomFreeService.exe",

    // Tanium
    "TaniumClient.exe",
    "TaniumCX.exe",
    "TaniumDetectEngine.exe",

    // Qualys
    "QualysAgent.exe",

    // HarfangLab
    "hurukai.exe",

    // Wazuh
    "wazuh-agent.exe",
    "ossec-agent.exe",

    // WithSecure (F-Secure)
    "fshoster32.exe",
    "fsgk32.exe",

    // Rapid7 InsightAgent
    "ir_agent.exe",

    // Malwarebytes
    "MBAMService.exe",
    "mbamtray.exe",

    // Sysmon
    "sysmon.exe",
    "Sysmon64.exe",
};

const size_t edrCount = sizeof(edrNames) / sizeof(edrNames[0]);
