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
				PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemPosition;//dos头
				TransFileAndMem::PCHDR32  pNtHeader = NULL;//nt头
				pNtHeader = (TransFileAndMem::PCHDR32)((DWORD)pDosHeader + pDosHeader->e_lfanew);

				//遍历节表 找到代码节的位置
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
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemPosition;//dos头
			TransFileAndMem::PCHDR32  pNtHeader = NULL;//nt头
			pNtHeader = (TransFileAndMem::PCHDR32)((DWORD)pDosHeader + pDosHeader->e_lfanew);

			//遍历节表 找到代码节的位置
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
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemPosition;//dos头
			TransFileAndMem::PCHDR32  pNtHeader = NULL;//nt头
			pNtHeader = (TransFileAndMem::PCHDR32)((DWORD)pDosHeader + pDosHeader->e_lfanew);

			//遍历节表 找到代码节的位置
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
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemPosition;//dos头
			TransFileAndMem::PCHDR32  pNtHeader = NULL;//nt头
			pNtHeader = (TransFileAndMem::PCHDR32)((DWORD)pDosHeader + pDosHeader->e_lfanew);

			//遍历节表 找到代码节的位置
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

#endif //空闲区添加代码
#if 1
		MYOBJECT_API BOOL PEChange::IsThereenoughTpaceToAddSectionTables(LPVOID lpvMemPosition)
		{
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpvMemPosition;//dos头
			PIMAGE_NT_HEADERS pNtHeader = NULL;//nt头
			pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
			DWORD dwSizeMax = pNtHeader->OptionalHeader.SizeOfHeaders;//整个头的最大大小
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + pNtHeader->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + sizeof(DWORD));

			pSectionHeader += pNtHeader->FileHeader.NumberOfSections; //来到空白节头
			DWORD dwSizeUsed = (DWORD)pSectionHeader - (DWORD)pDosHeader;
			PBYTE pTemp = (PBYTE)pSectionHeader;
			//判断是否有足够的空间容纳连续的节表 

			for (size_t i = 0; i < 2 * sizeof(IMAGE_SECTION_HEADER); ++i);
			{
				//单纯的空间太小了
				if (dwSizeUsed >= dwSizeMax)
					return false;
				//可能节表之后是有用的数据 我们不能覆盖
				if (*pTemp != 0x00 && *pTemp != 0xcc)
					return false;
				pTemp++;
				dwSizeUsed++;
			}

			return true;
		
		}
		MYOBJECT_API LPVOID PEChange::GetMorePositon(LPVOID lpvMemPosition)
		{
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpvMemPosition;//dos头
			PIMAGE_NT_HEADERS pNtHeaderOriGin = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaderOriGin + pNtHeaderOriGin->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + sizeof(DWORD));
			pSectionHeader += pNtHeaderOriGin->FileHeader.NumberOfSections; //来到空白节头
#if	0
			if (IsThereenoughTpaceToAddSectionTables(lpvMemPosition))
				return LPVOID(pSectionHeader);

#endif

			pDosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER);
			PBYTE pNtHeaderNew = PBYTE((DWORD)pDosHeader + pDosHeader->e_lfanew);
			PBYTE pNtHeaderOld = (PBYTE)pNtHeaderOriGin;

			//拷贝所有头
			for (; pNtHeaderOld != (PBYTE)pSectionHeader; pNtHeaderNew++,pNtHeaderOld++)
			{
				*pNtHeaderNew = *pNtHeaderOld;
			}
			//清空剩余区域
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
			memcpy_s(pSectionHeader->Name, 8, abName, 8);//名字

			pSectionHeader->PointerToRawData = pSectionHeaderLast->PointerToRawData + pSectionHeaderLast->SizeOfRawData;
			pSectionHeader->VirtualAddress = pSectionHeaderLast->VirtualAddress + ((pSectionHeaderLast->SizeOfRawData > pSectionHeaderLast->Misc.VirtualSize) ? pSectionHeaderLast->SizeOfRawData : pSectionHeaderLast->Misc.VirtualSize);
			pSectionHeader->SizeOfRawData = dwRawSize;

			return PVOID(pSectionHeader->PointerToRawData);

		}
		MYOBJECT_API PVOID PEChange::AddTheSection(LPVOID lpvMemPosition, DWORD dwRawSize,DWORD dwVirtualSize, DWORD dwCharacteristics, const BYTE(&abName)[8])
		{
			//获取新节表地址
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)GetMorePositon(lpvMemPosition);
			if (pSectionHeader == NULL)
				return  NULL; //没有足够的空间容纳节表 退出
			//添加并修正新的节表
			auto p =AddTheSectionTable(pSectionHeader, dwRawSize, dwVirtualSize, dwCharacteristics, abName);
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpvMemPosition;//dos头
			PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);//nt头
			//虚拟地址对齐
			pSectionHeader->VirtualAddress += pNtHeader->OptionalHeader.SectionAlignment;
			pSectionHeader->VirtualAddress -= pSectionHeader->VirtualAddress % pNtHeader->OptionalHeader.SectionAlignment;
			pNtHeader->OptionalHeader.SizeOfImage += dwRawSize; //修正内存映像大小
			pNtHeader->FileHeader.NumberOfSections += 1; //修正节数量
			return p;
		}
		MYOBJECT_API DWORD PEChange::GetFileBufferWithAnNewSection(LPVOID pFileBuffer, DWORD dwFileSize, LPVOID* pImageBuffer, DWORD dwSize)
		{
			_IMAGE_DOS_HEADER* pDosHeader;//dos头
			PIMAGE_NT_HEADERS pNtHeader;//nt头
			//dwSize += 0x20;//多留点空白
			uint32_t dSectionPosition;

			//dos头
			pDosHeader = (_IMAGE_DOS_HEADER*)pFileBuffer;
			if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			{
#if _DEBUG
				printf("读取的文件不是标准PE文件");
#endif
				return STATUS_INVALID_IMAGE_FORMAT;
			}

			//NT头
			pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
			if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
			{
#if _DEBUG
				printf("读取的文件不是标准PE文件");
#endif
				return STATUS_INVALID_IMAGE_FORMAT;
			}

			//分配内存
			*pImageBuffer = VirtualAlloc(NULL, dwFileSize + dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (*pImageBuffer == NULL)
			{
#if _DEBUG
				printf("VirtualAlloc filed error=%d", GetLastError());
#endif
				return GetLastError();
			}
			memset(*pImageBuffer, 0, dwFileSize +dwSize);
			//拷贝原始文件
			memcpy(*pImageBuffer, pFileBuffer, dwFileSize);

			return STATUS_SUCCESS;
		}

		MYOBJECT_API PVOID PEChange::MoveTheExportTable(PVOID pvPosition, vecExports& vecExport)
		{
			PIMAGE_EXPORT_DIRECTORY pied = PIMAGE_EXPORT_DIRECTORY(vecExport.uFoa + (uint32_t)_lpvFileAddSection);
			//原始的导出表目录项
			//1.复制AddressOfFunctions
			PVOID pvTemp = PVOID((uint32_t)_lpvFileAddSection + _tf.RvaToFoa(_lpvFileAddSection, pied->AddressOfFunctions));
			memcpy(pvPosition, pvTemp,pied->NumberOfFunctions*4);
			PVOID pvNewFunc = pvPosition;
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, pied->NumberOfFunctions * 4);

			//2.复制AddressOfNameOridinals
			pvTemp = ADDRESS_ADD_DWORD(_lpvFileAddSection, _tf.RvaToFoa(_lpvFileAddSection, pied->AddressOfNameOrdinals));
			memcpy(pvPosition, pvTemp, pied->NumberOfNames * 2);
			PVOID pvNewOrid = pvPosition;
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, pied->NumberOfNames * 2);

			//3.复制AddressOfNames
			pvTemp = ADDRESS_ADD_DWORD(_lpvFileAddSection, _tf.RvaToFoa(_lpvFileAddSection, pied->AddressOfNames));
			memcpy(pvPosition, pvTemp, pied->NumberOfNames * 4);
			PVOID pvNewName = pvPosition;
			uint32_t* pNameRVA = (uint32_t*)pvPosition; //用于修复函数名rva
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, pied->NumberOfNames * 4);

			//4.复制函数名 并修复函数名RVA
			size_t nSize = vecExport.vecstrNames.size();
			size_t nSizeName;
			uint32_t uFoa;
			for (size_t i = 0; i < nSize; ++i)
			{
				nSizeName = vecExport.vecstrNames[i].size()+1;
				memcpy(pvPosition, vecExport.vecstrNames[i].c_str(), nSizeName);//拷贝函数名
				uFoa = ADDRESS_SUB_DWORD(pvPosition, _lpvFileAddSection);//获取foa
				*pNameRVA = _tf.FoaToRva(_lpvFileAddSection, uFoa);//修正RVA
				pNameRVA++;
				pvPosition = ADDRESS_ADD_DWORD(pvPosition, nSizeName);//下一个地址
			}

			//5.修复IMAGE_EXPORT_DIRECTORY中的RVA并将其复制IMAGE_EXPORT_DIRECTORY结构
			uFoa = ADDRESS_SUB_DWORD(pvNewFunc, _lpvFileAddSection);//新的FOA
			pied->AddressOfFunctions = _tf.FoaToRva(_lpvFileAddSection, uFoa);//新的RVA
			uFoa = ADDRESS_SUB_DWORD(pvNewOrid, _lpvFileAddSection);//新的FOA
			pied->AddressOfNameOrdinals = _tf.FoaToRva(_lpvFileAddSection, uFoa);//新的RVA
			uFoa = ADDRESS_SUB_DWORD(pvNewName, _lpvFileAddSection);//新的FOA
			pied->AddressOfNames = _tf.FoaToRva(_lpvFileAddSection, uFoa);//新的RVA
			//修复RVA
			memcpy(pvPosition, pied, sizeof(IMAGE_EXPORT_DIRECTORY));
			PVOID pvNewied = pvPosition;
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, sizeof(IMAGE_EXPORT_DIRECTORY));//用于返回的地址

			//6.修复目录表中的IMAGE_EXPORT_DIRECTORY的RVA
			PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER)_lpvFileAddSection;
			PIMAGE_NT_HEADERS32 pNtHead = (PIMAGE_NT_HEADERS32)((DWORD)_lpvFileAddSection + pDosHead->e_lfanew);
			uFoa = ADDRESS_SUB_DWORD(pvNewied, _lpvFileAddSection);//新的FOA

			pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress =
				_tf.FoaToRva(_lpvFileAddSection, uFoa);//新的RVA


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
				pReloc = (PIMAGE_BASE_RELOCATION)(ADDRESS_ADD_DWORD(pReloc, pReloc->SizeOfBlock));//来到下一个重定位块
			}
			//最后拷贝8字节代表重定位表结束
			memcpy(pvPosition, pReloc, 8);
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, 8);
			 
			PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER)_lpvFileAddSection;
			PIMAGE_NT_HEADERS32 pNtHead = (PIMAGE_NT_HEADERS32)((DWORD)_lpvFileAddSection + pDosHead->e_lfanew);
			uint32_t uFoa = ADDRESS_SUB_DWORD(pvReloc, _lpvFileAddSection);//新的FOA
			pNtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress =
				_tf.FoaToRva(_lpvFileAddSection, uFoa);//新的RVA
			return pvPosition;
		}
		MYOBJECT_API PVOID PEChange::ImportInject(PVOID pvPosition, PCSTR szInjectDllName, PCSTR szInjectDllFuncName)
		{
			DWORD dwCopySize = 0;
			PIMAGE_DOS_HEADER  pDosHeader = (PIMAGE_DOS_HEADER)_lpvFileAddSection;
			PIMAGE_NT_HEADERS32 pNtHeader = (PIMAGE_NT_HEADERS32)(ADDRESS_ADD_DWORD(_lpvFileAddSection, pDosHeader->e_lfanew));
			DWORD dwFoaAndRva = _tf.RvaToFoa(_lpvFileAddSection,pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
			PIMAGE_IMPORT_DESCRIPTOR  pImport = (PIMAGE_IMPORT_DESCRIPTOR)(ADDRESS_ADD_DWORD(dwFoaAndRva, _lpvFileAddSection));
			/*找到原始导入表的地址*/

			//先修正导入表的新的地址
			dwFoaAndRva = _tf.FoaToRva(_lpvFileAddSection, ADDRESS_SUB_DWORD(pvPosition, _lpvFileAddSection));
			_lpvFileAddSection, pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = dwFoaAndRva; //修改为新的RVA
			while (pImport->FirstThunk) //直到最后一个导入表
			{
				memcpy(pvPosition, pImport, sizeof(IMAGE_IMPORT_DESCRIPTOR));
				pImport++;
				pvPosition = (PVOID)(ADDRESS_ADD_DWORD(pvPosition, sizeof(IMAGE_IMPORT_DESCRIPTOR)));
			}
			/*拷贝所有的导入表结构到指定位置*/

			pImport = PIMAGE_IMPORT_DESCRIPTOR(pvPosition);
			pvPosition = (PVOID)(ADDRESS_ADD_DWORD(pvPosition, 2*sizeof(IMAGE_IMPORT_DESCRIPTOR)));//要空一个空的导入表项
			pImport->TimeDateStamp = 0;
			pImport->ForwarderChain = 0;
			/*添加一个我们的DLL导入表项*/

			dwCopySize = strlen(szInjectDllName)+1;
			memcpy(pvPosition, szInjectDllName, dwCopySize);
			dwFoaAndRva = _tf.FoaToRva(_lpvFileAddSection, ADDRESS_SUB_DWORD(pvPosition, _lpvFileAddSection));
			pImport->Name = dwFoaAndRva;//修正我们的导入表名字RVA
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, dwCopySize);
			/*拷贝我们的DLL名字 并修正我们的导入表*/

			PDWORD pInt = (PDWORD)pvPosition;
			memset(pvPosition, 0, 8); //清空8个字节 作为我们的INT表（最后一个为0）
			dwFoaAndRva = _tf.FoaToRva(_lpvFileAddSection, ADDRESS_SUB_DWORD(pInt, _lpvFileAddSection));
			pImport->OriginalFirstThunk = dwFoaAndRva;
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, 8);

			PDWORD pIat = (PDWORD)pvPosition;
			memset(pvPosition, 0, 8);//清空8个字节 作为我们的IAT表（最后一个为0）
			dwFoaAndRva = _tf.FoaToRva(_lpvFileAddSection, ADDRESS_SUB_DWORD(pIat, _lpvFileAddSection));
			pImport->FirstThunk = dwFoaAndRva;
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, 8);
			/*设置我们的INT和IAT表 并修正我们的导入表*/

			memset(pvPosition, 0, 2);//清空2个字节 作为IMAGE_IMPORT_BY_NAME 和HINT
			dwCopySize = strlen(szInjectDllFuncName)+1;
			memcpy(ADDRESS_ADD_DWORD(pvPosition,2), szInjectDllFuncName, dwCopySize);//再拷贝名字
			dwFoaAndRva = _tf.FoaToRva(_lpvFileAddSection, ADDRESS_SUB_DWORD(pvPosition, _lpvFileAddSection));
			*pInt = dwFoaAndRva;//修正我们的INT表
			*pIat = dwFoaAndRva;//修正我们的IAT表
			pvPosition = ADDRESS_ADD_DWORD(pvPosition, dwCopySize+2);
			/*拷贝我们的函数名 并修正我们的iat表和INT表*/

			return pvPosition;
		}
#endif //新增节添加代码
#if 1
		MYOBJECT_API bool PEChange::ExpandLastSection(DWORD dwSize, DWORD dwVirtualSize)
		{
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemPosition;//dos头
			PIMAGE_NT_HEADERS pNtHeader = NULL;//nt头
			pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
			
			dwSize += pNtHeader->OptionalHeader.FileAlignment;
			dwSize -= dwSize % pNtHeader->OptionalHeader.FileAlignment;
			//对齐处理

			DWORD dwSizeToAlloc = pNtHeader->OptionalHeader.SizeOfImage;
			dwSizeToAlloc += dwSize;
			//获取需要扩大的大小

			_lpvMemMergeLastSection = VirtualAlloc(NULL, dwSizeToAlloc, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (_lpvMemMergeLastSection == NULL)
			{
#if _DEBUG
				printf("VirtualAlloc  _lpvMemMergeLastSection Error,Error Code = <%d>\r\n", GetLastError());
#endif
				return false;
			}
			//申请空间
			memcpy_s(_lpvMemMergeLastSection, dwSizeToAlloc, _lpvMemPosition, pNtHeader->OptionalHeader.SizeOfImage);
			//拷贝原始内存
			memset(LPVOID((DWORD)_lpvMemMergeLastSection+ pNtHeader->OptionalHeader.SizeOfImage), 0, dwSize);
			//新增的空间清零
			/*生成新的内存映像*/

			pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemMergeLastSection;//dos头
			pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);//nt头
			pNtHeader->OptionalHeader.SizeOfImage = dwSizeToAlloc;
			//修正SizeOfImage

			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + pNtHeader->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + sizeof(DWORD));//来到节表
			pSectionHeader += pNtHeader->FileHeader.NumberOfSections -1; //来到最后一个节的头部

			pSectionHeader->Misc.VirtualSize += dwVirtualSize;
			pSectionHeader->SizeOfRawData += dwSize;
			_tf.CopyImageBufferToNewBuffer(_lpvMemMergeLastSection, &_lpvFileMergeLastSection);//内存映像到文件映像
			if (_lpvFileMergeLastSection == NULL)
			{
#if _DEBUG
				printf("_lpvMemMergeLastSection to  _lpvFileMergeLastSection Error,Error Code = <%d>\r\n", GetLastError());
#endif
				VirtualFree(_lpvMemMergeLastSection, 0, MEM_RELEASE);
				_lpvMemMergeLastSection = NULL;
			}
			/*生成文件映像*/

			_tf._uNewSize = _tf.m_GetFileSize(_lpvFileMergeLastSection);//修正newfile的大小
			_tf.MemeryTOFile(_lpvFileMergeLastSection, _tf._uNewSize, TEXT("PeMergeLastSection.exe"));
			_tf._lpvNewFilePosition = _lpvFileMergeLastSection;
			_tf._lpvNewMemPosition = _lpvMemMergeLastSection;
			//修改内存中文件映像和内存映像

			//释放最初的文件new映像和内存映像
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
			/*修正我们类的地址*/

		}
#endif//扩大最后一个节
#if 1

		MYOBJECT_API bool PEChange::MergeAllSections()
		{
			if (_lpvMemPosition == NULL)
			{
				_lpvMemPosition = _tf._lpvNewMemPosition;
				if (_lpvMemPosition == NULL)
					return false; //没有转换为内存映像 则返回false
			}
				
			PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemPosition;//dos头
			PIMAGE_NT_HEADERS pNtHeader = NULL;//nt头
			pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);//nt头地址
			DWORD dwNumber = 1;
	
			PIMAGE_SECTION_HEADER pSectionHeaderFirst = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + pNtHeader->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + sizeof(DWORD));
			while (!pSectionHeaderFirst->PointerToRawData)
			{
				++pSectionHeaderFirst;
				++dwNumber;//节的数量++
			}//跳过文件位置为0的节
			PIMAGE_SECTION_HEADER pSectionHeaderRemain = pSectionHeaderFirst;//剩下的节

			for (DWORD i = 1; i < pNtHeader->FileHeader.NumberOfSections - dwNumber; ++i)
			{
				pSectionHeaderFirst->Characteristics |= (++pSectionHeaderRemain)->Characteristics;//遍历剩下的节 修正节的属性
				memset(pSectionHeaderRemain, 0, sizeof(IMAGE_SECTION_HEADER));//清空节表
			}//遍历所有节表 除了最后一个 修正节的属性 并清空节表

			pSectionHeaderFirst->Characteristics |= (++pSectionHeaderRemain)->Characteristics;
			//pSectionHeaderRemain 指向最后一个节表 修正属性
			DWORD dwSizeOfHeaders = GetTheVauleAfterAlignment(pSectionHeaderFirst->VirtualAddress, pNtHeader->OptionalHeader.SectionAlignment);//获取开头节表的头
			pSectionHeaderFirst->SizeOfRawData = GetTheVauleAfterAlignment(pSectionHeaderRemain->VirtualAddress + pSectionHeaderRemain->SizeOfRawData - 
				dwSizeOfHeaders, pNtHeader->OptionalHeader.FileAlignment);//获取新的文件大小
			pSectionHeaderFirst->Misc.VirtualSize = pSectionHeaderRemain->VirtualAddress - dwSizeOfHeaders + pSectionHeaderRemain->Misc.VirtualSize;//获取新的有用代码大小

			memset(pSectionHeaderRemain, 0, sizeof(IMAGE_SECTION_HEADER));//清空最后一个节表

			//节的数量变成dwNumber
			pNtHeader->FileHeader.NumberOfSections = dwNumber;

			if (_lpvFilePosition)
			{
				VirtualFree(_lpvMemPosition, 0, MEM_RELEASE);
				_lpvFilePosition = NULL;
			}//原来的对应文件映像如果存在的化 释放掉

			_tf.CopyImageBufferToNewBuffer(_lpvMemPosition, &_lpvFilePosition);//内存映像到文件映像
			if (_lpvFilePosition == NULL)
			{
#if _DEBUG
				printf("_lpvMemPosition to  _lpvFilePosition Error,Error Code = <%d>\r\n", GetLastError());
#endif
			}
			/*生成文件映像*/

			_tf._uNewSize = _tf.m_GetFileSize(_lpvFilePosition);//修正newfile的大小
			_tf.MemeryTOFile(_lpvFilePosition, _tf._uNewSize, TEXT("PeMergeSection.exe"));
			_tf._lpvNewFilePosition = _lpvFilePosition;
			_tf._lpvNewMemPosition = _lpvMemPosition;
			//修改内存中文件映像和内存映像


			return true;
		}
#endif //合并所有节

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
				//修正messagebox偏移
				DWORD dwMessageBox = (DWORD)pec.GetCallAddress((LPVOID)MESSAGEBOXA, a.first, 8);
				//修正跳转真实oep的偏移
				DWORD dwOep = (DWORD)pec.GetCallAddress((LPVOID)pe.entryPoint(), a.first, 13);
				*(PDWORD)&abShellCode[9] = dwMessageBox;
				*(PDWORD)&abShellCode[14] = dwOep;
				//拷贝shellcode
				pec.CopyShellCode(abShellCode, a.first);
				pec.FixOep(a.first);
			}
#endif

#if 0
			auto a = pec.GetFreeCodeLocation(sizeof(abShellCode));
			if (a.first != nullptr && a.second != nullptr)
			{
				//修正messagebox偏移
				DWORD dwMessageBox = (DWORD)pec.GetCallAddress((LPVOID)MESSAGEBOXA, a.first, 8);
				//修正跳转真实oep的偏移
				DWORD dwOep = (DWORD)pec.GetCallAddress((LPVOID)pe.entryPoint(), a.first, 13);
				*(PDWORD)&abShellCode[9] = dwMessageBox;
				*(PDWORD)&abShellCode[14] = dwOep;
				//拷贝shellcode
				pec.CopyShellCode(abShellCode, a.first);
				pec.FixOep(a.first);
			}
			else
			{
				a = pec.GetFreeLocation(sizeof(abShellCode));
				if (a.first != nullptr && a.second != nullptr)
				{
					//修正messagebox偏移
					DWORD dwMessageBox = (DWORD)pec.GetCallAddress((LPVOID)MESSAGEBOXA, a.first, 8);
					//修正跳转真实oep的偏移
					DWORD dwOep = (DWORD)pec.GetCallAddress((LPVOID)pe.entryPoint(), a.first, 13);
					*(PDWORD)&abShellCode[9] = dwMessageBox;
					*(PDWORD)&abShellCode[14] = dwOep;
					//拷贝shellcode
					pec.CopyShellCode(abShellCode, a.first);
					pec.FixOep(a.first);
				}
			}
#endif
		}
#endif //实验程序
	}
}