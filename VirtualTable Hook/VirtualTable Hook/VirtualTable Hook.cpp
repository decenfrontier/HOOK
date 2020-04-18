#include <windows.h>
#include <stdio.h>

class Base
{
public:
	int a;
	int b;
	virtual void print()
	{
		printf("I am Base\n");
	}
};

void MyHookPrint()
{
	printf("你被Hook了\n");
}

int main()
{
	Base* pb = new Base();

	// 1 取出虚表首地址
	DWORD* pVtAddr = (DWORD*)*(DWORD*)pb;
	// 2 修改内存页的保护属性
	DWORD dwOldProtect = 0;
	VirtualProtect(pVtAddr, 4, PAGE_READWRITE, &dwOldProtect);
	// 3 修改虚表第一个函数的地址
	*pVtAddr = (DWORD)MyHookPrint;
	// 4 恢复内存页的保护属性
	VirtualProtect(pVtAddr, 4, dwOldProtect, 0);

	pb->print();
	delete pb;
	getchar();
	return 0;
}