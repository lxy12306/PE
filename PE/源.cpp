#include "../Include/HandleGuard.h"
#include "../PE/PEImage.h"
#include "../PE/PEChange.h"
#include "../Include/Winheaders.h"
#include <stdio.h>
#include "../PE/TransFileAndMem.h"
#include "../Include/Macro.h"

#include <iostream>

using std::cout;
using std::endl;


int main()
{
	using namespace MyObject::pe;

	PEImage pe;
	NTSTATUS ntstatus = pe.Load_Write(TEXT("Hello2.exe"));

	if (!NT_SUCCESS(ntstatus))
		return 0;

#if 0
	if (NT_SUCCESS(ntstatus))
	{
		printf("%s", "打开文件成功");
		auto vecpSection = pe.pSections();
		for (auto p : vecpSection)
		{
			printf("%.8s\r\n", p->Name);
		}//打印节信息 

		vecExports vec;
		pe.ShowDirectory();//展示目录表
		pe.GetExports(vec);//获取导出表
		vec.e_ShowExportData();//展示导出表
	}
#endif

#if 0
	pe.ShowImports(pe.GetImports());//打印导入表
	pe.ShowBoundImport(pe.GetBoundPort());//打印导出表
	vecReloc vecRelocTemp; 
	pe.GetReloc(vecRelocTemp); //获取重定位表
	vecRelocTemp.e_ShowReloc();//展示从定位表

#endif //

	TransFileAndMem tfam((LPVOID)pe.base(), pe.size());

	//tfam.FixTheImageBase(0x500000, vecRelocTemp); //修正重定位

#if 1
	PEChange pecg(tfam);
	BYTE abName[8] = ".123";
	LPVOID lpvBuffer = NULL;
	if ((lpvBuffer = pecg.FileAddAnNewSection((LPVOID)pe.base(), pe.size(), 0x2000, 0xE0000060, abName, abName)))
	{
		pecg.ImportInject(lpvBuffer, "Dll1.dll", "aaaaaaa");
		tfam.writeBackNewFile( TEXT("notepad2.exe"));
	}
#endif //新增节 移动导出表 重定位表 导入表注入

#if 0

	BYTE abName[8] = ".123";
	LPVOID lpvBuffer = NULL;

	if (pecg.FileAddAnNewSection((LPVOID)pe.base(), pe.size(), 0x1000, 0xE0000060, abName, abName))
	{
		lpvBuffer = pecg.GetlpAddNewSection();
		tfam.SetAddress(lpvBuffer);
		tfam.SetSize(pe.size() + 0x1000);
	}
#endif// 新增节添加代码



#if 0
	tfam.transformFileToImage();
	pecg.MergeLastSection(0x999);
	tfam.writeBackNewFile(TEXT("Dll2.dll"));
#endif //扩大最后一个节

#if 0
	tfam.transformFileToImage();
	pecg.MergeAllSections();
	tfam.writeBackNewFile(TEXT("Dll2.dll"));
#endif //合并所有节


#if 0
	InsertShelloCode(tfam, pe); 

#endif //代码段插入shellcode
	//tfam.transformImageToFile();
	//LPVOID temp = tfam.m_Position_FoatoImage((LPVOID)0x400);
	//temp = tfam.m_Position_ImagetoFile(temp);

	//tfam.writeBackOldFile( TEXT("Hello2.exe"));
	ntstatus = LastNtStatus();
	return 0;
}