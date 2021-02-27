#include "PEChange.h"

namespace MyObject
{

	namespace pe
	{
#define ADDRESS_ADD_DWORD(x,y) ((PVOID)((DWORD)(x)+(DWORD)(y)))
#define ADDRESS_SUB_DWORD(x,y) ((DWORD)((DWORD)(x)-(DWORD)(y)))
#if 1
		LPVOID PEChange::m_GetVaInCodeSection(LPVOID lpvPosition)
		{
			if (_isPe32)
			{
				PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemPosition;//dosͷ
				TransFileAndMem::PCHDR32  pNtHeader = NULL;//ntͷ
				pNtHeader = (TransFileAndMem::PCHDR32)((DWORD)pDosHeader + pDosHeader->e_lfanew);

				//�����ڱ� �ҵ�����ڵ�λ��
				PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + pNtHeader->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + sizeof(DWORD));

				for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i, ++pSectionHeader)
				{	
					if (pSectionHeader->Characteristics & IMAGE_SCN_CNT_CODE)
					{
#if _DEBUG
						printf("%.8s", pSectionHeader->Name);
#endif
						if ((DWORD)lpvPosition >= pSectionHeader->VirtualAddress && (DWORD)lpvPosition >= pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData)
						{
							return LPVOID((DWORD)lpvPosition - (DWORD)pDosHeader + pNtHeader->OptionalHeader.ImageBase);
						}
					}
				}
				return NULL;

			}
			return NULL;
		}

		LPVOID PEChange::GetCallAddress(LPVOID lpvAddress, LPVOID lpvPosition,DWORD dwPianYiOfPosition)
		{
			if (_isPe32)
			{
				lpvPosition = m_GetVaInCodeSection(lpvPosition);
				if (!lpvPosition)
					return NULL;

				DWORD dwPianYi = DWORD(lpvAddress) - 5 - DWORD(lpvPosition) - dwPianYiOfPosition;
				return LPVOID(dwPianYi);
			}
			return NULL;
		}

		std::pair<LPVOID, LPVOID> PEChange::m_GetFreeCodeLocation(DWORD dwSize)
		{
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemPosition;//dosͷ
			TransFileAndMem::PCHDR32  pNtHeader = NULL;//ntͷ
			pNtHeader = (TransFileAndMem::PCHDR32)((DWORD)pDosHeader + pDosHeader->e_lfanew);

			//�����ڱ� �ҵ�����ڵ�λ��
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + pNtHeader->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + sizeof(DWORD));

			for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i, ++pSectionHeader)
			{
				if (pSectionHeader->Characteristics & IMAGE_SCN_CNT_CODE)
				{
#if _DEBUG
					printf("%.8s", pSectionHeader->Name);
#endif
					if(pSectionHeader->SizeOfRawData > pSectionHeader->Misc.VirtualSize+ dwSize)
						return std::make_pair((LPVOID)(pSectionHeader->VirtualAddress+ pSectionHeader->Misc.VirtualSize), (LPVOID)(pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData));

				}
			}
			return std::make_pair(nullptr, nullptr);
		}

		std::pair<LPVOID, LPVOID> PEChange::m_GetFreeLocation(PIMAGE_SECTION_HEADER* ppSectionHeader, DWORD dwSize)
		{
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemPosition;//dosͷ
			TransFileAndMem::PCHDR32  pNtHeader = NULL;//ntͷ
			pNtHeader = (TransFileAndMem::PCHDR32)((DWORD)pDosHeader + pDosHeader->e_lfanew);

			//�����ڱ� �ҵ�����ڵ�λ��
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + pNtHeader->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + sizeof(DWORD));

			for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i, ++pSectionHeader)
			{
				if (pSectionHeader->SizeOfRawData > pSectionHeader->Misc.VirtualSize + dwSize)
				{
					return std::make_pair((LPVOID)(pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize), (LPVOID)(pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData));
				}
			}
			return std::make_pair(nullptr, nullptr);
		}
		std::pair<LPVOID, LPVOID> PEChange::m_GetFreeLocation(PIMAGE_SECTION_HEADER *ppSectionHeader,DWORD dwSize,DWORD dwNumOfSection = 1)
		{
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemPosition;//dosͷ
			TransFileAndMem::PCHDR32  pNtHeader = NULL;//ntͷ
			pNtHeader = (TransFileAndMem::PCHDR32)((DWORD)pDosHeader + pDosHeader->e_lfanew);

			//�����ڱ� �ҵ�����ڵ�λ��
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + pNtHeader->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + sizeof(DWORD));
			pSectionHeader += dwNumOfSection;
#if _DEBUG
			printf("%.8s", pSectionHeader->Name);
#endif
			if (pSectionHeader->SizeOfRawData > pSectionHeader->Misc.VirtualSize + dwSize)
			{
				*ppSectionHeader = pSectionHeader;
				return std::make_pair((LPVOID)(pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize), (LPVOID)(pSectionHeader->VirtualAddress + pSectionHeader->SizeOfRawData));
			}

			return std::make_pair(nullptr, nullptr);
		}

#endif //��������Ӵ���
#if 1
		MYOBJECT_API BOOL PEChange::IsThereenoughTpaceToAddSectionTables(LPVOID lpvMemPosition)
		{
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpvMemPosition;//dosͷ
			PIMAGE_NT_HEADERS pNtHeader = NULL;//ntͷ
			pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
			DWORD dwSizeMax = pNtHeader->OptionalHeader.SizeOfHeaders;//����ͷ������С
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + pNtHeader->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + sizeof(DWORD));

			pSectionHeader += pNtHeader->FileHeader.NumberOfSections; //�����հ׽�ͷ
			DWORD dwSizeUsed = (DWORD)pSectionHeader - (DWORD)pDosHeader;
			PBYTE pTemp = (PBYTE)pSectionHeader;
			//�ж��Ƿ����㹻�Ŀռ����������Ľڱ� 

			for (size_t i = 0; i < 2 * sizeof(IMAGE_SECTION_HEADER); ++i);
			{
				//�����Ŀռ�̫С��
				if (dwSizeUsed >= dwSizeMax)
					return false;
				//���ܽڱ�֮�������õ����� ���ǲ��ܸ���
				if (*pTemp != 0x00 && *pTemp != 0xcc)
					return false;
				pTemp++;
				dwSizeUsed++;
			}

			return true;
		
		}
		MYOBJECT_API LPVOID PEChange::GetMorePositon(LPVOID lpvMemPosition)
		{
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpvMemPosition;//dosͷ
			PIMAGE_NT_HEADERS pNtHeaderOriGin = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaderOriGin + pNtHeaderOriGin->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + sizeof(DWORD));
			pSectionHeader += pNtHeaderOriGin->FileHeader.NumberOfSections; //�����հ׽�ͷ
#if	0
			if (IsThereenoughTpaceToAddSectionTables(lpvMemPosition))
				return LPVOID(pSectionHeader);

#endif

			pDosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER);
			PBYTE pNtHeaderNew = PBYTE((DWORD)pDosHeader + pDosHeader->e_lfanew);
			PBYTE pNtHeaderOld = (PBYTE)pNtHeaderOriGin;

			//��������ͷ
			for (; pNtHeaderOld != (PBYTE)pSectionHeader; pNtHeaderNew++,pNtHeaderOld++)
			{
				*pNtHeaderNew = *pNtHeaderOld;
			}
			//���ʣ������
			LPVOID lpvRet = pNtHeaderNew;
			for (; pNtHeaderNew != (PBYTE)pSectionHeader; pNtHeaderNew++)
			{
				*pNtHeaderNew = 0x00;
			}
			if (IsThereenoughTpaceToAddSectionTables(lpvMemPosition))
				return lpvRet;
			return NULL;

		}
		MYOBJECT_API PVOID PEChange::AddTheSectionTable(PIMAGE_SECTION_HEADER pSectionHeader,DWORD dwRawSize,  DWORD dwVirtualSize,DWORD dwCharacteristics, const BYTE (&abName)[8])
		{

			PIMAGE_SECTION_HEADER pSectionHeaderLast = pSectionHeader - 1;
			pSectionHeader->Characteristics = dwCharacteristics;
			pSectionHeader->Misc.VirtualSize = dwVirtualSize;
			memcpy_s(pSectionHeader->Name, 8, abName, 8);//����

			pSectionHeader->PointerToRawData = pSectionHeaderLast->PointerToRawData + pSectionHeaderLast->SizeOfRawData;
			pSectionHeader->VirtualAddress = pSectionHeaderLast->VirtualAddress + ((pSectionHeaderLast->SizeOfRawData > pSectionHeaderLast->Misc.VirtualSize) ? pSectionHeaderLast->SizeOfRawData : pSectionHeaderLast->Misc.VirtualSize);
			pSectionHeader->SizeOfRawData = dwRawSize;

			return PVOID(pSectionHeader->PointerToRawData);

		}
		MYOBJECT_API PVOID PEChange::AddTheSection(LPVOID lpvMemPosition, DWORD dwRawSize,DWORD dwVirtualSize, DWORD dwCharacteristics, const BYTE(&abName)[8])
		{
			//��ȡ�½ڱ��ַ
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)GetMorePositon(lpvMemPosition);
			if (pSectionHeader == NULL)
				return  NULL; //û���㹻�Ŀռ����ɽڱ� �˳�
			//��Ӳ������µĽڱ�
			auto p =AddTheSectionTable(pSectionHeader, dwRawSize, dwVirtualSize, dwCharacteristics, abName);
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpvMemPosition;//dosͷ
			PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);//ntͷ
			//�����ַ����
			pSectionHeader->VirtualAddress += pNtHeader->OptionalHeader.SectionAlignment;
			pSectionHeader->VirtualAddress -= pSectionHeader->VirtualAddress % pNtHeader->OptionalHeader.SectionAlignment;
			pNtHeader->OptionalHeader.SizeOfImage += dwRawSize; //�����ڴ�ӳ���С
			pNtHeader->FileHeader.NumberOfSections += 1; //����������
			return p;
		}
		MYOBJECT_API DWORD PEChange::GetFileBufferWithAnNewSection(LPVOID pFileBuffer, DWORD dwFileSize, LPVOID* pImageBuffer, DWORD dwSize)
		{
			_IMAGE_DOS_HEADER* pDosHeader;//dosͷ
			PIMAGE_NT_HEADERS pNtHeader;//ntͷ
			//dwSize += 0x20;//������հ�
			uint32_t dSectionPosition;

			//dosͷ
			pDosHeader = (_IMAGE_DOS_HEADER*)pFileBuffer;
			if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			{
#if _DEBUG
				printf("��ȡ���ļ����Ǳ�׼PE�ļ�");
#endif
				return STATUS_INVALID_IMAGE_FORMAT;
			}

			//NTͷ
			pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
			if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
			{
#if _DEBUG
				printf("��ȡ���ļ����Ǳ�׼PE�ļ�");
#endif
				return STATUS_INVALID_IMAGE_FORMAT;
			}

			//�����ڴ�
			*pImageBuffer = VirtualAlloc(NULL, dwFileSize + dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (*pImageBuffer == NULL)
			{
#if _DEBUG
				printf("VirtualAlloc filed error=%d", GetLastError());
#endif
				return GetLastError();
			}
			memset(*pImageBuffer, 0, dwFileSize +dwSize);
			//����ԭʼ�ļ�
			memcpy(*pImageBuffer, pFileBuffer, dwFileSize);

			return STATUS_SUCCESS;
		}

		MYOBJECT_API PVOID PEChange::MoveTheExportTable(PVOID pvPosition, vecExports& vecExport)
		{
			PIMAGE_EXPORT_DIRECTORY pied = PIMAGE_EXPORT_DIRECTORY(vecExport.uFoa + (uint32_t)_lpvFileAddSection);
			//ԭʼ�ĵ�����Ŀ¼��
			//1.����AddressOfFunctions
			PVOID pvTemp = PVOID((uint32_t)_lpvFileAddSection + _tf.RvaToFoa(_lpvFileAddSection, pied->AddressOfFunctions));
			memcpy(pvPosition, pvTemp,pied->NumberOfFunctions*4);
			PVOID pvNewFunc = pvPosition;
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, pied->NumberOfFunctions * 4);

			//2.����AddressOfNameOridinals
			pvTemp = ADDRESS_ADD_DWORD(_lpvFileAddSection, _tf.RvaToFoa(_lpvFileAddSection, pied->AddressOfNameOrdinals));
			memcpy(pvPosition, pvTemp, pied->NumberOfNames * 2);
			PVOID pvNewOrid = pvPosition;
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, pied->NumberOfNames * 2);

			//3.����AddressOfNames
			pvTemp = ADDRESS_ADD_DWORD(_lpvFileAddSection, _tf.RvaToFoa(_lpvFileAddSection, pied->AddressOfNames));
			memcpy(pvPosition, pvTemp, pied->NumberOfNames * 4);
			PVOID pvNewName = pvPosition;
			uint32_t* pNameRVA = (uint32_t*)pvPosition; //�����޸�������rva
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, pied->NumberOfNames * 4);

			//4.���ƺ����� ���޸�������RVA
			size_t nSize = vecExport.vecstrNames.size();
			size_t nSizeName;
			uint32_t uFoa;
			for (size_t i = 0; i < nSize; ++i)
			{
				nSizeName = vecExport.vecstrNames[i].size()+1;
				memcpy(pvPosition, vecExport.vecstrNames[i].c_str(), nSizeName);//����������
				uFoa = ADDRESS_SUB_DWORD(pvPosition, _lpvFileAddSection);//��ȡfoa
				*pNameRVA = _tf.FoaToRva(_lpvFileAddSection, uFoa);//����RVA
				pNameRVA++;
				pvPosition = ADDRESS_ADD_DWORD(pvPosition, nSizeName);//��һ����ַ
			}

			//5.�޸�IMAGE_EXPORT_DIRECTORY�е�RVA�����临��IMAGE_EXPORT_DIRECTORY�ṹ
			uFoa = ADDRESS_SUB_DWORD(pvNewFunc, _lpvFileAddSection);//�µ�FOA
			pied->AddressOfFunctions = _tf.FoaToRva(_lpvFileAddSection, uFoa);//�µ�RVA
			uFoa = ADDRESS_SUB_DWORD(pvNewOrid, _lpvFileAddSection);//�µ�FOA
			pied->AddressOfNameOrdinals = _tf.FoaToRva(_lpvFileAddSection, uFoa);//�µ�RVA
			uFoa = ADDRESS_SUB_DWORD(pvNewName, _lpvFileAddSection);//�µ�FOA
			pied->AddressOfNames = _tf.FoaToRva(_lpvFileAddSection, uFoa);//�µ�RVA
			//�޸�RVA
			memcpy(pvPosition, pied, sizeof(IMAGE_EXPORT_DIRECTORY));
			PVOID pvNewied = pvPosition;
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, sizeof(IMAGE_EXPORT_DIRECTORY));//���ڷ��صĵ�ַ

			//6.�޸�Ŀ¼���е�IMAGE_EXPORT_DIRECTORY��RVA
			PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER)_lpvFileAddSection;
			PIMAGE_NT_HEADERS32 pNtHead = (PIMAGE_NT_HEADERS32)((DWORD)_lpvFileAddSection + pDosHead->e_lfanew);
			uFoa = ADDRESS_SUB_DWORD(pvNewied, _lpvFileAddSection);//�µ�FOA

			pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress =
				_tf.FoaToRva(_lpvFileAddSection, uFoa);//�µ�RVA


			return pvPosition;

		}
		MYOBJECT_API PVOID PEChange::MoveTheRelocTable(PVOID pvPosition, vecReloc& vecRelocs)
		{
			PIMAGE_BASE_RELOCATION pReloc = PIMAGE_BASE_RELOCATION(ADDRESS_ADD_DWORD(_lpvFileAddSection, vecRelocs.uFoaOFReloc));
			
			PVOID pvReloc = pvPosition;
			for (size_t i = 0; i < vecRelocs.e_Size(); ++i)
			{
				memcpy(pvPosition, pReloc, pReloc->SizeOfBlock);
				pvPosition = ADDRESS_ADD_DWORD(pvPosition, pReloc->SizeOfBlock);
				pReloc = (PIMAGE_BASE_RELOCATION)(ADDRESS_ADD_DWORD(pReloc, pReloc->SizeOfBlock));//������һ���ض�λ��
			}
			//��󿽱�8�ֽڴ����ض�λ�����
			memcpy(pvPosition, pReloc, 8);
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, 8);
			 
			PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER)_lpvFileAddSection;
			PIMAGE_NT_HEADERS32 pNtHead = (PIMAGE_NT_HEADERS32)((DWORD)_lpvFileAddSection + pDosHead->e_lfanew);
			uint32_t uFoa = ADDRESS_SUB_DWORD(pvReloc, _lpvFileAddSection);//�µ�FOA
			pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress =
				_tf.FoaToRva(_lpvFileAddSection, uFoa);//�µ�RVA
			return pvPosition;
		}
		MYOBJECT_API PVOID PEChange::ImportInject(PVOID pvPosition, PCSTR szInjectDllName, PCSTR szInjectDllFuncName)
		{
			DWORD dwCopySize = 0;
			PIMAGE_DOS_HEADER  pDosHeader = (PIMAGE_DOS_HEADER)_lpvFileAddSection;
			PIMAGE_NT_HEADERS32 pNtHeader = (PIMAGE_NT_HEADERS32)(ADDRESS_ADD_DWORD(_lpvFileAddSection, pDosHeader->e_lfanew));
			DWORD dwFoaAndRva = _tf.RvaToFoa(_lpvFileAddSection,pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			PIMAGE_IMPORT_DESCRIPTOR  pImport = (PIMAGE_IMPORT_DESCRIPTOR)(ADDRESS_ADD_DWORD(dwFoaAndRva, _lpvFileAddSection));
			/*�ҵ�ԭʼ�����ĵ�ַ*/

			//�������������µĵ�ַ
			dwFoaAndRva = _tf.FoaToRva(_lpvFileAddSection, ADDRESS_SUB_DWORD(pvPosition, _lpvFileAddSection));
			_lpvFileAddSection, pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = dwFoaAndRva; //�޸�Ϊ�µ�RVA
			while (pImport->FirstThunk) //ֱ�����һ�������
			{
				memcpy(pvPosition, pImport, sizeof(IMAGE_IMPORT_DESCRIPTOR));
				pImport++;
				pvPosition = (PVOID)(ADDRESS_ADD_DWORD(pvPosition, sizeof(IMAGE_IMPORT_DESCRIPTOR)));
			}
			/*�������еĵ����ṹ��ָ��λ��*/

			pImport = PIMAGE_IMPORT_DESCRIPTOR(pvPosition);
			pvPosition = (PVOID)(ADDRESS_ADD_DWORD(pvPosition, 2*sizeof(IMAGE_IMPORT_DESCRIPTOR)));//Ҫ��һ���յĵ������
			pImport->TimeDateStamp = 0;
			pImport->ForwarderChain = 0;
			/*���һ�����ǵ�DLL�������*/

			dwCopySize = strlen(szInjectDllName)+1;
			memcpy(pvPosition, szInjectDllName, dwCopySize);
			dwFoaAndRva = _tf.FoaToRva(_lpvFileAddSection, ADDRESS_SUB_DWORD(pvPosition, _lpvFileAddSection));
			pImport->Name = dwFoaAndRva;//�������ǵĵ��������RVA
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, dwCopySize);
			/*�������ǵ�DLL���� ���������ǵĵ����*/

			PDWORD pInt = (PDWORD)pvPosition;
			memset(pvPosition, 0, 8); //���8���ֽ� ��Ϊ���ǵ�INT�����һ��Ϊ0��
			dwFoaAndRva = _tf.FoaToRva(_lpvFileAddSection, ADDRESS_SUB_DWORD(pInt, _lpvFileAddSection));
			pImport->OriginalFirstThunk = dwFoaAndRva;
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, 8);

			PDWORD pIat = (PDWORD)pvPosition;
			memset(pvPosition, 0, 8);//���8���ֽ� ��Ϊ���ǵ�IAT�����һ��Ϊ0��
			dwFoaAndRva = _tf.FoaToRva(_lpvFileAddSection, ADDRESS_SUB_DWORD(pIat, _lpvFileAddSection));
			pImport->FirstThunk = dwFoaAndRva;
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, 8);
			/*�������ǵ�INT��IAT�� ���������ǵĵ����*/

			memset(pvPosition, 0, 2);//���2���ֽ� ��ΪIMAGE_IMPORT_BY_NAME ��HINT
			dwCopySize = strlen(szInjectDllFuncName)+1;
			memcpy(ADDRESS_ADD_DWORD(pvPosition,2), szInjectDllFuncName, dwCopySize);//�ٿ�������
			dwFoaAndRva = _tf.FoaToRva(_lpvFileAddSection, ADDRESS_SUB_DWORD(pvPosition, _lpvFileAddSection));
			*pInt = dwFoaAndRva;//�������ǵ�INT��
			*pIat = dwFoaAndRva;//�������ǵ�IAT��
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, dwCopySize+2);
			/*�������ǵĺ����� ���������ǵ�iat���INT��*/

			return pvPosition;
		}
#endif //��������Ӵ���
#if 1
		MYOBJECT_API bool PEChange::ExpandLastSection(DWORD dwSize, DWORD dwVirtualSize)
		{
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemPosition;//dosͷ
			PIMAGE_NT_HEADERS pNtHeader = NULL;//ntͷ
			pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
			
			dwSize += pNtHeader->OptionalHeader.FileAlignment;
			dwSize -= dwSize % pNtHeader->OptionalHeader.FileAlignment;
			//���봦��

			DWORD dwSizeToAlloc = pNtHeader->OptionalHeader.SizeOfImage;
			dwSizeToAlloc += dwSize;
			//��ȡ��Ҫ����Ĵ�С

			_lpvMemMergeLastSection = VirtualAlloc(NULL, dwSizeToAlloc, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (_lpvMemMergeLastSection == NULL)
			{
#if _DEBUG
				printf("VirtualAlloc  _lpvMemMergeLastSection Error,Error Code = <%d>\r\n", GetLastError());
#endif
				return false;
			}
			//����ռ�
			memcpy_s(_lpvMemMergeLastSection, dwSizeToAlloc, _lpvMemPosition, pNtHeader->OptionalHeader.SizeOfImage);
			//����ԭʼ�ڴ�
			memset(LPVOID((DWORD)_lpvMemMergeLastSection+ pNtHeader->OptionalHeader.SizeOfImage), 0, dwSize);
			//�����Ŀռ�����
			/*�����µ��ڴ�ӳ��*/

			pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemMergeLastSection;//dosͷ
			pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);//ntͷ
			pNtHeader->OptionalHeader.SizeOfImage = dwSizeToAlloc;
			//����SizeOfImage

			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + pNtHeader->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + sizeof(DWORD));//�����ڱ�
			pSectionHeader += pNtHeader->FileHeader.NumberOfSections -1; //�������һ���ڵ�ͷ��

			pSectionHeader->Misc.VirtualSize += dwVirtualSize;
			pSectionHeader->SizeOfRawData += dwSize;
			_tf.CopyImageBufferToNewBuffer(_lpvMemMergeLastSection, &_lpvFileMergeLastSection);//�ڴ�ӳ���ļ�ӳ��
			if (_lpvFileMergeLastSection == NULL)
			{
#if _DEBUG
				printf("_lpvMemMergeLastSection to  _lpvFileMergeLastSection Error,Error Code = <%d>\r\n", GetLastError());
#endif
				VirtualFree(_lpvMemMergeLastSection, 0, MEM_RELEASE);
				_lpvMemMergeLastSection = NULL;
			}
			/*�����ļ�ӳ��*/

			_tf._uNewSize = _tf.m_GetFileSize(_lpvFileMergeLastSection);//����newfile�Ĵ�С
			_tf.MemeryTOFile(_lpvFileMergeLastSection, _tf._uNewSize, TEXT("PeMergeLastSection.exe"));
			_tf._lpvNewFilePosition = _lpvFileMergeLastSection;
			_tf._lpvNewMemPosition = _lpvMemMergeLastSection;
			//�޸��ڴ����ļ�ӳ����ڴ�ӳ��

			//�ͷ�������ļ�newӳ����ڴ�ӳ��
			if (_lpvFilePosition)
			{
				VirtualFree(_lpvFilePosition, 0, MEM_RELEASE);
				_lpvFilePosition = _lpvFileMergeLastSection;
			}
			if (_lpvMemPosition)
			{
				VirtualFree(_lpvMemPosition, 0, MEM_RELEASE);
				_lpvMemPosition = _lpvMemMergeLastSection;
			}
			/*����������ĵ�ַ*/

		}
#endif//�������һ����
#if 1

		MYOBJECT_API bool PEChange::MergeAllSections()
		{
			if (_lpvMemPosition == NULL)
			{
				_lpvMemPosition = _tf._lpvNewMemPosition;
				if (_lpvMemPosition == NULL)
					return false; //û��ת��Ϊ�ڴ�ӳ�� �򷵻�false
			}
				
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemPosition;//dosͷ
			PIMAGE_NT_HEADERS pNtHeader = NULL;//ntͷ
			pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);//ntͷ��ַ
			DWORD dwNumber = 1;
	
			PIMAGE_SECTION_HEADER pSectionHeaderFirst = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + pNtHeader->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + sizeof(DWORD));
			while (!pSectionHeaderFirst->PointerToRawData)
			{
				++pSectionHeaderFirst;
				++dwNumber;//�ڵ�����++
			}//�����ļ�λ��Ϊ0�Ľ�
			PIMAGE_SECTION_HEADER pSectionHeaderRemain = pSectionHeaderFirst;//ʣ�µĽ�

			for (DWORD i = 1; i < pNtHeader->FileHeader.NumberOfSections - dwNumber; ++i)
			{
				pSectionHeaderFirst->Characteristics |= (++pSectionHeaderRemain)->Characteristics;//����ʣ�µĽ� �����ڵ�����
				memset(pSectionHeaderRemain, 0, sizeof(IMAGE_SECTION_HEADER));//��սڱ�
			}//�������нڱ� �������һ�� �����ڵ����� ����սڱ�

			pSectionHeaderFirst->Characteristics |= (++pSectionHeaderRemain)->Characteristics;
			//pSectionHeaderRemain ָ�����һ���ڱ� ��������
			DWORD dwSizeOfHeaders = GetTheVauleAfterAlignment(pSectionHeaderFirst->VirtualAddress, pNtHeader->OptionalHeader.SectionAlignment);//��ȡ��ͷ�ڱ��ͷ
			pSectionHeaderFirst->SizeOfRawData = GetTheVauleAfterAlignment(pSectionHeaderRemain->VirtualAddress + pSectionHeaderRemain->SizeOfRawData - 
				dwSizeOfHeaders, pNtHeader->OptionalHeader.FileAlignment);//��ȡ�µ��ļ���С
			pSectionHeaderFirst->Misc.VirtualSize = pSectionHeaderRemain->VirtualAddress - dwSizeOfHeaders + pSectionHeaderRemain->Misc.VirtualSize;//��ȡ�µ����ô����С

			memset(pSectionHeaderRemain, 0, sizeof(IMAGE_SECTION_HEADER));//������һ���ڱ�

			//�ڵ��������dwNumber
			pNtHeader->FileHeader.NumberOfSections = dwNumber;

			if (_lpvFilePosition)
			{
				VirtualFree(_lpvMemPosition, 0, MEM_RELEASE);
				_lpvFilePosition = NULL;
			}//ԭ���Ķ�Ӧ�ļ�ӳ��������ڵĻ� �ͷŵ�

			_tf.CopyImageBufferToNewBuffer(_lpvMemPosition, &_lpvFilePosition);//�ڴ�ӳ���ļ�ӳ��
			if (_lpvFilePosition == NULL)
			{
#if _DEBUG
				printf("_lpvMemPosition to  _lpvFilePosition Error,Error Code = <%d>\r\n", GetLastError());
#endif
			}
			/*�����ļ�ӳ��*/

			_tf._uNewSize = _tf.m_GetFileSize(_lpvFilePosition);//����newfile�Ĵ�С
			_tf.MemeryTOFile(_lpvFilePosition, _tf._uNewSize, TEXT("PeMergeSection.exe"));
			_tf._lpvNewFilePosition = _lpvFilePosition;
			_tf._lpvNewMemPosition = _lpvMemPosition;
			//�޸��ڴ����ļ�ӳ����ڴ�ӳ��


			return true;
		}
#endif //�ϲ����н�

#if 1
		void InsertShelloCode(TransFileAndMem& tfam, PEImage& pe)
		{
			PEChange pec(tfam);
#define MESSAGEBOXA 0x749B1930
			BYTE abShellCode[] = {
			0x6a,0x00,
			0x6a,0x00,
			0x6a,0x00,
			0x6a,0x00,
			0xE8,
			0x00,0x00,0x00,0x00,
			0xE9,
			0x00,0x00,0x00,0x00 };

#if 1
			auto a = pec.GetFreeLocation(sizeof(abShellCode),1);
			if (a.first != nullptr && a.second != nullptr)
			{
				//����messageboxƫ��
				DWORD dwMessageBox = (DWORD)pec.GetCallAddress((LPVOID)MESSAGEBOXA, a.first, 8);
				//������ת��ʵoep��ƫ��
				DWORD dwOep = (DWORD)pec.GetCallAddress((LPVOID)pe.entryPoint(), a.first, 13);
				*(PDWORD)&abShellCode[9] = dwMessageBox;
				*(PDWORD)&abShellCode[14] = dwOep;
				//����shellcode
				pec.CopyShellCode(abShellCode, a.first);
				pec.FixOep(a.first);
			}
#endif

#if 0
			auto a = pec.GetFreeCodeLocation(sizeof(abShellCode));
			if (a.first != nullptr && a.second != nullptr)
			{
				//����messageboxƫ��
				DWORD dwMessageBox = (DWORD)pec.GetCallAddress((LPVOID)MESSAGEBOXA, a.first, 8);
				//������ת��ʵoep��ƫ��
				DWORD dwOep = (DWORD)pec.GetCallAddress((LPVOID)pe.entryPoint(), a.first, 13);
				*(PDWORD)&abShellCode[9] = dwMessageBox;
				*(PDWORD)&abShellCode[14] = dwOep;
				//����shellcode
				pec.CopyShellCode(abShellCode, a.first);
				pec.FixOep(a.first);
			}
			else
			{
				a = pec.GetFreeLocation(sizeof(abShellCode));
				if (a.first != nullptr && a.second != nullptr)
				{
					//����messageboxƫ��
					DWORD dwMessageBox = (DWORD)pec.GetCallAddress((LPVOID)MESSAGEBOXA, a.first, 8);
					//������ת��ʵoep��ƫ��
					DWORD dwOep = (DWORD)pec.GetCallAddress((LPVOID)pe.entryPoint(), a.first, 13);
					*(PDWORD)&abShellCode[9] = dwMessageBox;
					*(PDWORD)&abShellCode[14] = dwOep;
					//����shellcode
					pec.CopyShellCode(abShellCode, a.first);
					pec.FixOep(a.first);
				}
			}
#endif
		}
#endif //ʵ�����
	}
}