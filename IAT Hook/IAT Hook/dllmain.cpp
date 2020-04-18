// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include "stdio.h"
#include <windows.h>

DWORD g_dwOldAddr;	// 原始函数地址
DWORD g_dwNewAddr;	// Hook函数地址
DWORD g_dwIATHookFlag = 0;	// Hook状态, 1Hook, 2未Hook

void DbgOutput(const char *szFormat, ...) {
#ifdef _DEBUG
	char szbufFormat[0x1000];
	char szBufFormat_Game[0x1010] = "CPALyth:";
	va_list argList;
	va_start(argList, szFormat);     //参数列表初始化
	vsprintf_s(szbufFormat, szFormat, argList);
	strcat_s(szBufFormat_Game, szbufFormat);
	OutputDebugStringA(szBufFormat_Game);
	va_end(argList);
#endif
}

BOOL SetIATHook(DWORD dwOldAddr, DWORD dwNewAddr)
{
	DbgOutput("开始SetIATHook\n");
	BOOL isFound = FALSE;
	DWORD dwImageBase = 0;
	DWORD* pFuncAddr = NULL;
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_IMPORT_DESCRIPTOR* pImportDescriptor = NULL;
	DWORD dwOldProtect = 0;
	__try
	{
		DWORD dwCount = 0;
		// 获取exe导入表的虚拟地址
		dwImageBase = (DWORD)GetModuleHandleA(NULL);	// 得到exe模块基址
		DbgOutput("dwImageBase=%X\n", dwImageBase);
		pNtHeader = (IMAGE_NT_HEADERS*)(dwImageBase + ((IMAGE_DOS_HEADER*)dwImageBase)->e_lfanew);
		DbgOutput("pNtHeader=%X\n", pNtHeader);
		pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)
			(dwImageBase + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		DbgOutput("pImportDescriptor=%X\n", pImportDescriptor);
		// 遍历IAT,找到这个函数的基址
		while (pImportDescriptor->FirstThunk != 0 && isFound == FALSE)
		{
			pFuncAddr = (DWORD*)(dwImageBase + pImportDescriptor->FirstThunk);
			while (*pFuncAddr)
			{
				DbgOutput("dwCount=%d,*pFuncAddr=%X,dwOldAddr=%X\n", dwCount++, *pFuncAddr, dwOldAddr);
				if (dwOldAddr == *pFuncAddr)	// 如果找到要HOOK的函数
				{
					DbgOutput("找到\n");
					VirtualProtect(pFuncAddr, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect);
					*pFuncAddr = dwNewAddr;	// 把导入表的函数地址 修改为 自定义函数地址
					VirtualProtect(pFuncAddr, sizeof(DWORD), dwOldProtect, 0);
					isFound = TRUE;
					break;
				}
				pFuncAddr++;
				DbgOutput("pFuncAddr=%X\n", pFuncAddr);
			}
			pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)((DWORD)pImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));	// 到下一个导入表
		}
	}
	__except(1)
	{
		DbgOutput("SetIATHook 异常\n");
	}
	DbgOutput("SetIATHook结束\n");
	g_dwOldAddr = dwOldAddr;
	g_dwNewAddr = dwNewAddr;
	g_dwIATHookFlag = 1;
	return isFound;
}

BOOL UnIATHook()
{
	BOOL isFound = FALSE;
	DWORD dwImageBase = 0;
	DWORD* pFuncAddr = NULL;
	IMAGE_NT_HEADERS* pNtHeader = NULL;
	IMAGE_IMPORT_DESCRIPTOR* pImportDescriptor = NULL;
	DWORD dwOldProtect = 0;
	if (g_dwIATHookFlag == 0)
	{
		DbgOutput("UnIATHook失败,尚未SetIATHook\n");
		return FALSE;
	}
	__try
	{
		// 得到模块基址
		dwImageBase = (DWORD)GetModuleHandleA(NULL);
		pNtHeader = (IMAGE_NT_HEADERS*)(dwImageBase + ((IMAGE_DOS_HEADER*)dwImageBase)->e_lfanew);
		pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)
			(dwImageBase + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		// 遍历IAT,找到这个函数的基址
		while (pImportDescriptor->FirstThunk != 0 && isFound == FALSE)
		{
			pFuncAddr = (DWORD*)(dwImageBase + pImportDescriptor->FirstThunk);
			while (*pFuncAddr)
			{
				if (g_dwNewAddr == *pFuncAddr)	// 如果找到要HOOK的函数
				{
					VirtualProtect(pFuncAddr, sizeof(DWORD), PAGE_READWRITE, &dwOldProtect);
					*pFuncAddr = g_dwOldAddr;	// 把导入表的函数地址 修改为 自定义函数地址
					VirtualProtect(pFuncAddr, sizeof(DWORD), dwOldProtect, 0);
					isFound = TRUE;
					break;
				}
				pFuncAddr++;
			}
			pImportDescriptor = (IMAGE_IMPORT_DESCRIPTOR*)(pImportDescriptor + sizeof(IMAGE_IMPORT_DESCRIPTOR));	// 到下一个导入表
		}
	}
	__except(1)
	{
		DbgOutput("UnIATHook 异常\n");
	}
	
	g_dwOldAddr = 0;
	g_dwNewAddr = 0;
	g_dwIATHookFlag = 0;
	return isFound;
}

int WINAPI MyMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	char lpNewText[] = "修改后的内容";	// 只修改MessageBox的内容
	typedef int (WINAPI *pFnMessageBox)(HWND, LPCTSTR, LPCTSTR, UINT);
	// 执行原来的真正的MessageBox函数
	int ret = ((pFnMessageBox)g_dwOldAddr)(hWnd, (LPCTSTR)lpNewText, lpCaption, uType);
	return ret;
}

DWORD WINAPI ThreadFunc(LPVOID lpParameter)
{
	// 保存原始函数的地址
	DWORD pOldFuncAddr = (DWORD)GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxA");
	DbgOutput("原始函数MessageBoxA的地址为:%X\n", pOldFuncAddr);
	// 安装或卸载Hook
	if (!g_dwIATHookFlag)
	{
		SetIATHook(pOldFuncAddr, (DWORD)MyMessageBox);
	}
	else
	{
		UnIATHook();
	}
	return 0;
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	{
		DbgOutput("dll加载成功!\n");
		HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ThreadFunc,
			NULL, NULL, NULL);
		CloseHandle(hThread);
	}
		break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
	{
		DbgOutput("dll剥离成功!\n");
		HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ThreadFunc,
			NULL, NULL, NULL);
		CloseHandle(hThread);
	}
        break;
    }
    return TRUE;
}

