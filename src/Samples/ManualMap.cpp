#include <BlackBone/Process/Process.h>
#include <3rd_party/VersionApi.h>

#include <iostream>
#include <set>
#include <detours.h>
using namespace blackbone;


/*
    Try to map calc.exe into current process
*/
std::set<std::wstring> nativeMods, modList;
void MapCalcFromFile()
{
    Process thisProc;
    thisProc.Attach( GetCurrentProcessId() );

    nativeMods.clear();
    modList.clear();

    nativeMods.emplace( L"combase.dll" );
    nativeMods.emplace( L"user32.dll" );
    if (WinVer().ver == Win7)
    {
        nativeMods.emplace( L"gdi32.dll" );
        nativeMods.emplace( L"msvcr120.dll" );
        nativeMods.emplace( L"msvcp120.dll" );
    }

    modList.emplace( L"windows.storage.dll" );
    modList.emplace( L"shell32.dll" );
    modList.emplace( L"shlwapi.dll" );

    auto callback = []( CallbackType type, void* /*context*/, Process& /*process*/, const ModuleData& modInfo )
    {
        if(type == PreCallback)
        {
            if(nativeMods.count(modInfo.name))
                return LoadData( MT_Native, Ldr_None );
        }
        else
        {
            if (modList.count( modInfo.name ))
                return LoadData( MT_Default, Ldr_ModList );
        }

        return LoadData( MT_Default, Ldr_None );
    };

    std::wcout << L"Manual image mapping test" << std::endl;
    std::wcout << L"Trying to map C:\\windows\\system32\\calc.exe into current process" << std::endl;

    auto image = thisProc.mmap().MapImage( L"C:\\windows\\system32\\calc.exe", ManualImports | RebaseProcess, callback );
    if (!image)
    {
        std::wcout << L"Mapping failed with error 0x" << std::hex << image.status
                   << L". " << Utils::GetErrorDescription( image.status ) << std::endl << std::endl;
    }
    else
        std::wcout << L"Successfully mapped, unmapping\n";

    thisProc.mmap().UnmapAllModules();
}

/*
    Try to map cmd.exe into current process from buffer
*/
void MapCmdFromMem()
{
    Process thisProc;
    thisProc.Attach( GetCurrentProcessId() );

    void* buf = nullptr;
    auto size = 0;

    std::wcout << L"Manual image mapping from buffer test" << std::endl;
    std::wcout << L"Trying to map C:\\windows\\system32\\cmd.exe into current process" << std::endl;

    // Get image context
    HANDLE hFile = CreateFileW( L"C:\\windows\\system32\\cmd.exe", FILE_GENERIC_READ, 0x7, 0, OPEN_EXISTING, 0, 0 );
    if (hFile != INVALID_HANDLE_VALUE)
    {
        DWORD bytes = 0;
        size = GetFileSize( hFile, NULL );
        buf = VirtualAlloc( NULL, size, MEM_COMMIT, PAGE_READWRITE );
        ReadFile( hFile, buf, size, &bytes, NULL );
        CloseHandle( hFile );
    }

    auto image = thisProc.mmap().MapImage( size, buf, false, CreateLdrRef | RebaseProcess | NoDelayLoad );
    if (!image)
    {
        std::wcout << L"Mapping failed with error 0x" << std::hex << image.status
                   << L". " << Utils::GetErrorDescription( image.status ) << std::endl << std::endl;
    }
    else
        std::wcout << L"Successfully mapped, unmapping\n";

    VirtualFree( buf, 0, MEM_RELEASE );

    thisProc.mmap().UnmapAllModules();
}


typedef DWORD(WINAPI* PFUNC_GetModuleFileNameW)(HMODULE hModule,
												LPWSTR  lpFilename,
												DWORD   nSize);
PFUNC_GetModuleFileNameW g_OldGetModuleFileNameW = nullptr;

HMODULE      g_hMainModule = NULL;
DWORD WINAPI ProxyGetModuleFileNameW(
	HMODULE hModule,
	LPWSTR  lpFilename,
	DWORD   nSize)
{
	if (hModule == g_hMainModule)
	{
		const wchar_t* modPath = L"H:\\Code\\UnrealProjects\\UMG_UI\\Output\\WindowsNoEditor\\Engine\\Binaries\\Win64\\UE4Game.exe";
		wcscpy_s(lpFilename, nSize, modPath);
		return wcslen(modPath);
	}

	return g_OldGetModuleFileNameW(hModule, lpFilename, nSize);
}


typedef BOOL(WINAPI* PFUNC_IsDebuggerPresent)();
PFUNC_IsDebuggerPresent g_OldIsDebuggerPresent = nullptr;
BOOL WINAPI ProxyIsDebuggerPresent()
{
	return FALSE;
}

void InstallHook(Process& process)
{
	auto expGetModuleFileNameW = process.modules().GetExport(L"kernel32.dll", "GetModuleFileNameW");
	g_OldGetModuleFileNameW = (PFUNC_GetModuleFileNameW)expGetModuleFileNameW->procAddress;
	g_OldIsDebuggerPresent = (PFUNC_IsDebuggerPresent)process.modules().GetExport(L"kernel32.dll", "IsDebuggerPresent")->procAddress;
	DetourTransactionBegin();

    DetourAttach(&g_OldGetModuleFileNameW, ProxyGetModuleFileNameW);
	DetourAttach(&g_OldIsDebuggerPresent, ProxyIsDebuggerPresent);

	DetourTransactionCommit();
}

uint64_t RunEntryPoint(Process& proc, const ModuleDataPtr& mod, const std::pair<void*, size_t>& fileData)
{
	auto     a      = AsmFactory::GetAssembler(mod->type);
	uint64_t result = 0;

	pe::PEImage mainImage;
	NTSTATUS    status = mainImage.Load(fileData.first, fileData.second);
	if (!NT_SUCCESS(status))
	{
		std::wcout << L"Loading main module failed.\n";
		return status;
	}

	g_hMainModule = (HMODULE)mainImage.imageBase();

	a->GenPrologue();

	// Prepare custom arguments
	ptr_t customArgumentsAddress = 0;
	//if (pCustomArgs)
	//{
	//	auto memBuf = proc.memory().Allocate(pCustomArgs->size() + sizeof(uint64_t), PAGE_EXECUTE_READWRITE, 0, false);
	//	if (!memBuf)
	//		return memBuf.status;

	//	memBuf->Write(0, pCustomArgs->size());
	//	memBuf->Write(sizeof(uint64_t), pCustomArgs->size(), pCustomArgs->data());
	//	customArgumentsAddress = memBuf->ptr();
	//}

	// Function order
	// TLS first, entry point last
	std::vector<ptr_t> tlsCallbacks;
	int                callbackCount = mainImage.GetTLSCallbacks(mod->baseAddress, tlsCallbacks);
	if (callbackCount)
	{
		// PTLS_CALLBACK_FUNCTION(pImage->ImageBase, dwReason, NULL);
		for (auto& pCallback : tlsCallbacks)
		{
			a->GenCall(pCallback, { mod->baseAddress, DLL_PROCESS_ATTACH, customArgumentsAddress });
		}
	}


	// EntryPoint
	auto entryPoint = mainImage.entryPoint(mod->baseAddress);
	if (entryPoint != 0)
	{
		a->GenCall(entryPoint, { mod->baseAddress, DLL_PROCESS_ATTACH, customArgumentsAddress });
		//proc.remote().SaveCallResult(*a);
	}

	// Set invalid return code offset to preserve one from DllMain
	// proc.remote().AddReturnWithEvent(*a, mod->type, rt_int32, ARGS_OFFSET);
	a->GenEpilogue();

	//NTSTATUS status = _process.remote().ExecInWorkerThread((*a)->make(), (*a)->getCodeSize(), result);
	//if (!NT_SUCCESS(status))
	//	return status;


	void* code = (*a)->make();
	typedef int (*FnEntry)();
	FnEntry entry = (FnEntry)code;
	result = entry();

	return result;
}

void MapUE4FromMem()
{
	Process thisProc;
	thisProc.Attach(GetCurrentProcessId());

	void* buf  = nullptr;
	auto  size = 0;

	std::wcout << L"Manual image mapping from buffer test" << std::endl;
	std::wcout << L"Trying to map H:\\Code\\UnrealProjects\\UMG_UI\\Output\\WindowsNoEditor\\Engine\\Binaries\\Win64\\UE4Game.exe into current process" << std::endl;

	// Get image context
	HANDLE hFile = CreateFileW(L"H:\\Code\\UnrealProjects\\UMG_UI\\Output\\WindowsNoEditor\\Engine\\Binaries\\Win64\\UE4Game.exe", FILE_GENERIC_READ, 0x7, 0, OPEN_EXISTING, 0, 0);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD bytes = 0;
		size        = GetFileSize(hFile, NULL);
		buf         = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
		ReadFile(hFile, buf, size, &bytes, NULL);
		CloseHandle(hFile);
	}

	auto image = thisProc.mmap().MapImage(size, buf, false, RebaseProcess | NoDelayLoad | NoExecute);
	if (!image)
	{
		std::wcout << L"Mapping failed with error 0x" << std::hex << image.status
				   << L". " << Utils::GetErrorDescription(image.status) << std::endl
				   << std::endl;
	}
	else
		std::wcout << L"Successfully mapped, unmapping\n";

    InstallHook(thisProc);

    RunEntryPoint(thisProc, *image, {buf, size});


	VirtualFree(buf, 0, MEM_RELEASE);

	thisProc.mmap().UnmapAllModules();
}
