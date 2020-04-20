// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <tchar.h>
#include <windows.h>
#include "stdio.h"
#include <atlstr.h>

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

class CILHook
{
public:
	CILHook()
	{
		m_dwHookAddr = NULL;
		ZeroMemory(m_bOldBytes, 5);
		ZeroMemory(m_bNewBytes, 5);
	}
	~CILHook()
	{
		UnHook();
	}

	VOID Hook(DWORD dwHookAddr, DWORD HookProc)
	{
		if (dwHookAddr != NULL)
		{
			m_dwHookAddr = dwHookAddr;
			ReadProcessMemory((HANDLE)-1, (LPCVOID)dwHookAddr, m_bOldBytes, 5, NULL);    // 保存修改前Hook地址处5个字节的内容到m_bOldBytes
			m_bNewBytes[0] = 0xE9;    // jmp Opcode
			*(DWORD *)(m_bNewBytes + 1) = HookProc - dwHookAddr - 5;
			WriteProcessMemory((HANDLE)-1, (LPVOID)dwHookAddr, m_bNewBytes, 5, NULL);
		}
	}
	VOID UnHook()
	{
		if (m_dwHookAddr != NULL)
		{
			WriteProcessMemory((HANDLE)-1, (LPVOID)m_dwHookAddr, m_bOldBytes, 5, NULL);
		}
	}
	VOID ReHook()
	{
		if (m_dwHookAddr != NULL)
		{
			WriteProcessMemory((HANDLE)-1, (LPVOID)m_dwHookAddr, m_bNewBytes, 5, NULL);
		}
	}
private:
	DWORD m_dwHookAddr;      // 要Hook的地址
	BYTE m_bOldBytes[5];    // 函数入口代码
	BYTE m_bNewBytes[5];    // Inline代码
};
CILHook g_ILHook;

// 注意Hook的函数的参数和类型要相同,无论你是否使用它
int WINAPI MyMessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) 
{
	g_ILHook.UnHook();       // 若在Hook的API中调用原来的API,要先恢复原来的代码,否则将会死循环

	int a = 1024;
	int b = 2048;
	int sum = a + b;
	CString str;
	str.Format(L"结果为:%d", sum);
	MessageBoxW(NULL, str.GetBuffer(), L"MessageBoxA被Hook了", MB_OK);

	g_ILHook.ReHook();    // 然后重新挂钩,方便后面继续监视MessageBoxA
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
		DbgOutput("dll加载成功\n");
		DWORD dwHookAddr = (DWORD)GetProcAddress(GetModuleHandle(L"user32.dll"), "MessageBoxA");    // 获取指定模块中函数的地址
		g_ILHook.Hook(dwHookAddr, (DWORD)MyMessageBoxA);
	}
		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
		g_ILHook.UnHook();
        break;
    }
    return TRUE;
}

