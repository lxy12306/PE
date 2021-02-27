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
		printf("%s", "���ļ��ɹ�");
		auto vecpSection = pe.pSections();
		for (auto p : vecpSection)
		{
			printf("%.8s\r\n", p->Name);
		}//��ӡ����Ϣ 

		vecExports vec;
		pe.ShowDirectory();//չʾĿ¼��
		pe.GetExports(vec);//��ȡ������
		vec.e_ShowExportData();//չʾ������
	}
#endif

#if 0
	pe.ShowImports(pe.GetImports());//��ӡ�����
	pe.ShowBoundImport(pe.GetBoundPort());//��ӡ������
	vecReloc vecRelocTemp; 
	pe.GetReloc(vecRelocTemp); //��ȡ�ض�λ��
	vecRelocTemp.e_ShowReloc();//չʾ�Ӷ�λ��

#endif //

	TransFileAndMem tfam((LPVOID)pe.base(), pe.size());

	//tfam.FixTheImageBase(0x500000, vecRelocTemp); //�����ض�λ

#if 1
	PEChange pecg(tfam);
	BYTE abName[8] = ".123";
	LPVOID lpvBuffer = NULL;
	if ((lpvBuffer = pecg.FileAddAnNewSection((LPVOID)pe.base(), pe.size(), 0x2000, 0xE0000060, abName, abName)))
	{
		pecg.ImportInject(lpvBuffer, "Dll1.dll", "aaaaaaa");
		tfam.writeBackNewFile( TEXT("notepad2.exe"));
	}
#endif //������ �ƶ������� �ض�λ�� �����ע��

#if 0

	BYTE abName[8] = ".123";
	LPVOID lpvBuffer = NULL;

	if (pecg.FileAddAnNewSection((LPVOID)pe.base(), pe.size(), 0x1000, 0xE0000060, abName, abName))
	{
		lpvBuffer = pecg.GetlpAddNewSection();
		tfam.SetAddress(lpvBuffer);
		tfam.SetSize(pe.size() + 0x1000);
	}
#endif// ��������Ӵ���



#if 0
	tfam.transformFileToImage();
	pecg.MergeLastSection(0x999);
	tfam.writeBackNewFile(TEXT("Dll2.dll"));
#endif //�������һ����

#if 0
	tfam.transformFileToImage();
	pecg.MergeAllSections();
	tfam.writeBackNewFile(TEXT("Dll2.dll"));
#endif //�ϲ����н�


#if 0
	InsertShelloCode(tfam, pe); 

#endif //����β���shellcode
	//tfam.transformImageToFile();
	//LPVOID temp = tfam.m_Position_FoatoImage((LPVOID)0x400);
	//temp = tfam.m_Position_ImagetoFile(temp);

	//tfam.writeBackOldFile( TEXT("Hello2.exe"));
	ntstatus = LastNtStatus();
	return 0;
}