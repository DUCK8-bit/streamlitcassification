#include <windows.h>

int main() {
    // Suspicious API usage
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);

    MessageBoxA(0, "This is a malicious sample!", "Malicious", MB_OK);
    return 0;
} 