// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <tchar.h>
#include <windows.h>
#include "stdio.h"

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

#define PATCH_LEN 5	// 若Hook破坏了3行汇编语句,则此值为这3行语句的字节数

DWORD dwHookAddr = 0;	// Hook地址
DWORD dwRetAddr = 0;	// 返回地址
BYTE bHookFlag = 0;		// Hook标志
BYTE byOriCode[PATCH_LEN] = { 0 };	// Hook地址处的原始硬编码
char szNewText[] = "InlineHook!";	// 要修改的内容

void __declspec(naked) MyMsgBox()
{
	__asm
	{
		// 1 保存寄存器
		pushad
		pushfd
		// 2 修改数据:esp+4是第一个参数,esp+8是第二个参数
		lea eax, dword ptr ds:[szNewText]
		mov dword PTR ss:[esp + 8],eax	// 需自定义修改的位置
		// 3 恢复寄存器
		popfd
		popad
		// 4 执行覆盖代码(需自己设置)
		mov edi,edi
		push ebp
		mov ebp,esp
		// 5 返回执行
		jmp dwRetAddr
	}
}

BOOL HookMessageBoxW()
{
	BYTE byJmpCode[PATCH_LEN] = { 0xE9 };	// 先全部初始化为0xE9
	DWORD dwOldProtect = 0;
	DbgOutput("开始HookMessageBoxW\n");
	__try
	{
		if (!bHookFlag)
		{
			// 1 存储原始字节到byOriCode数组
			memcpy(byOriCode, (LPVOID)dwHookAddr, PATCH_LEN);
			// 2 初始化byJmpCode
			memset(&byJmpCode[1], 0x90, PATCH_LEN - 1);	// 第一个0xE9(Jmp)不变,后面全部替换为0x90(NOP)
			// 3 写入跳转地址到byJmpCode数组
			*(DWORD*)&byJmpCode[1] = (DWORD)MyMsgBox - (DWORD)dwHookAddr - 5;
			// 4 开始patch
			VirtualProtect((LPVOID)dwHookAddr, PATCH_LEN, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			memcpy((LPVOID)dwHookAddr, byJmpCode, PATCH_LEN);	// 写入跳转代码
			VirtualProtect((LPVOID)dwHookAddr, PATCH_LEN, dwOldProtect, 0);
			bHookFlag = TRUE;
		}
		else
		{
			// 1 卸载时直接写入原始代码
			VirtualProtect((LPVOID)dwHookAddr, PATCH_LEN, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			memcpy((LPVOID)dwHookAddr, byOriCode, PATCH_LEN);	// 写入原始代码
			VirtualProtect((LPVOID)dwHookAddr, PATCH_LEN, dwOldProtect, 0);
			bHookFlag = FALSE;
		}
		return TRUE;
	}
	__except(1)
	{
		DbgOutput("HookMessageBox() 异常\n");
		return FALSE;
	}
}

void SetHook()
{
	dwHookAddr = (DWORD)GetProcAddress(LoadLibrary(_T("user32.dll")), "MessageBoxW");	// 可自定义
	DbgOutput("dwHookAddr = %X\n", dwHookAddr);
	dwRetAddr = dwHookAddr + PATCH_LEN;
	HookMessageBoxW();
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
		SetHook();
	}
		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
	{
		DbgOutput("dll卸载成功\n");
		SetHook();
	}
        break;
    }
    return TRUE;
}

