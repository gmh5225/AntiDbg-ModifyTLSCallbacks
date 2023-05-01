#include <Windows.h>
#include <stdio.h>
#include <ImageHlp.h>
#pragma comment(lib, "ImageHlp")


void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved);
//linker spec
#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#else
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#endif
EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif
//end linker

//tls import
PIMAGE_TLS_CALLBACK _tls_callback = TLSCallbacks;
#pragma data_seg ()
#pragma const_seg ()
//end 
// tls declaration
void NTAPI __stdcall TLSCallbacks(PVOID DllHandle, DWORD dwReason, PVOID Reserved)
{
	printf("In TLSCallbacks\n");
	//ExitProcess(0);
}

bool ModifyTLSCallbacks(UINT64 newCallbackAddress) //you can edit this routine to work with multiple tls callbacks, this is just a proof of concept
{
	unsigned long cDirSize = 0;
	IMAGE_TLS_DIRECTORY* tlsDirectory;

	tlsDirectory = (IMAGE_TLS_DIRECTORY*)ImageDirectoryEntryToData(GetModuleHandle(NULL), TRUE, IMAGE_DIRECTORY_ENTRY_TLS, &cDirSize);
	if (!tlsDirectory)
	{
		printf("tlsDirectory = null\n");
		return false;
	}
	
	DWORD dOldProt = 0;

	if (!VirtualProtect((LPVOID)tlsDirectory->AddressOfCallBacks, sizeof(UINT64), PAGE_EXECUTE_READWRITE, &dOldProt))
	{
		printf("VirtualProtect failed\n");
		return false;
	}
	
	auto oldCallback = tlsDirectory->AddressOfCallBacks;
	
	printf("memcpy 1\n");
	//memcpy((void*)tlsDirectory->AddressOfCallBacks, &newCallbackAddress, sizeof(UINT64)); //this writes over the pointer to the callback, not the callback itself
	WriteProcessMemory((HANDLE)-1, (void*)tlsDirectory->AddressOfCallBacks, &newCallbackAddress, sizeof(UINT64), NULL);
	printf("memcpy 2\n");

	printf("memcpy 3\n");
	WriteProcessMemory((HANDLE)-1, (void*)tlsDirectory->AddressOfCallBacks, &oldCallback, sizeof(UINT64), NULL);
	//tlsDirectory->AddressOfCallBacks = oldCallback;
	printf("memcpy 4\n");
	
	return true;
}

int main(void)
{
	if (ModifyTLSCallbacks((UINT64)GetModuleHandle(NULL))) //this will block x64dbg, CE debugger, etc.
	{
		printf("Modified tls callback successfully!\n");
	}

	system("pause");
	return 0;
}
