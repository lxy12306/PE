#pragma once
#include "TransFileAndMem.h"
#include "PEImage.h"
#include "../UseFulFuction.h"

namespace MyObject
{

namespace pe
{
		class PEChange
		{

		public:
			MYOBJECT_API PEChange(TransFileAndMem& tf) :_tf(tf),_lpvFilePosition(tf._lpvNewFilePosition), _lpvMemPosition(tf._lpvNewMemPosition), _isPe32(tf._bFileIs32){}
			MYOBJECT_API ~PEChange()
			{
				if (_lpvFileAddSection)
					VirtualFree(_lpvFileAddSection, 0, MEM_RELEASE);
			}
#if 1
/// <summary>
/// 在已有的块中添加数据
/// </summary>
			
			/// <summary>
			/// 获取要e8 或者 e9的地址的相对偏移
			/// </summary>
			/// <param name="lpvAddress">要调用的地址</param>
			/// <param name="lpvPosition">内存区域的基址</param>
			/// <param name="dwPianYi">内存区域的偏移</param>
			/// <returns>转换好的偏移</returns>
			MYOBJECT_API LPVOID GetCallAddress(LPVOID lpvAddress,LPVOID lpvPosition,DWORD dwPianYi = 0);
			/// <summary>
			/// 获取空白代码区域
			/// </summary>
			/// <param name="dwSize">空白区域的最小的大小</param>
			/// <returns>空白起始位置位置和结束位置</returns>
			MYOBJECT_API std::pair<LPVOID, LPVOID> GetFreeCodeLocation(DWORD dwSize = 0)
			{
				auto ret = m_GetFreeCodeLocation(dwSize);
				if (_isPe32)
				{
					ret.first = LPVOID(DWORD(_lpvMemPosition) + DWORD(ret.first));
					ret.second = LPVOID(DWORD(_lpvMemPosition) + DWORD(ret.second));
				}
				return ret;
			}
			/// <summary>
			/// 获取指定节的空白位置 并将节置为可执行
			/// </summary>
			/// <param name="dwSize">最小的大小</param>
			/// <param name="dwNumOfSection">第几个节</param>
			/// <returns>空白起始位置位置和结束位置</returns>
			MYOBJECT_API std::pair<LPVOID, LPVOID> GetFreeLocation(DWORD dwSize, DWORD dwNumOfSection )
			{
				PIMAGE_SECTION_HEADER pSectionHeader = NULL;
				auto ret = m_GetFreeLocation(&pSectionHeader, dwSize,dwNumOfSection);
				if(pSectionHeader != NULL)									//如果该区段有空白地址可用
					pSectionHeader->Characteristics |= IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE;//修正可执行属性
				else
					return std::pair<LPVOID, LPVOID>(nullptr,nullptr);
				if (_isPe32)
				{
					ret.first = LPVOID(DWORD(_lpvMemPosition) + DWORD(ret.first));
					ret.second = LPVOID(DWORD(_lpvMemPosition) + DWORD(ret.second));
				}
				return ret;
			}
			/// <summary>
			/// 获取所有节的可能空白位置 并将节置为可执行
			/// </summary>
			/// <param name="dwSize">最小的大小</param>
			/// <returns>空白起始位置位置和结束位置</returns>
			MYOBJECT_API std::pair<LPVOID, LPVOID> GetFreeLocation(DWORD dwSize = 0)
			{
				PIMAGE_SECTION_HEADER pSectionHeader = NULL;
				auto ret = m_GetFreeLocation(&pSectionHeader,dwSize);
				if (pSectionHeader != NULL)									//如果有区段有空白地址可用
					pSectionHeader->Characteristics |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;//修正可执行属性
				else
					return std::pair<LPVOID, LPVOID>(nullptr, nullptr);
				if (_isPe32)
				{
					ret.first = LPVOID(DWORD(_lpvMemPosition) + DWORD(ret.first));
					ret.second = LPVOID(DWORD(_lpvMemPosition) + DWORD(ret.second));
				}
				return ret;
			}

			/// <summary>
			/// 将ope修正为我们需要的地址
			/// </summary>
			/// <param name="lpvAddress">需要修正为的地址</param>
			/// <returns>无</returns>
			MYOBJECT_API inline void FixOep(LPVOID lpvAddress)
			{
				if (_isPe32)
				{
					PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemPosition;//dos头
					PIMAGE_NT_HEADERS pNtHeader = NULL;//nt头
					pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
					pNtHeader->OptionalHeader.AddressOfEntryPoint = (DWORD)lpvAddress - (DWORD)_lpvMemPosition;
				}
			}
			/// <summary>
			/// 拷贝shellcode
			/// </summary>
			/// <param name="abShellocod">shellcode数组</param>
			/// <param name="lpAddress">拷贝到的地址</param>
			/// <returns>是否成功</returns>
			MYOBJECT_API template<size_t N>
			BOOL CopyShellCode(BYTE(&abShellocod)[N], LPVOID lpAddress);
		private:
			/// <summary>
			/// 获取输入地址在真实内存映像的地址
			/// </summary>
			/// <param name="lpvPosition">我们的在_lpvMemPosition开头的PE文件的VA</param>
			/// <returns>地址</returns>
			MYOBJECT_API LPVOID m_GetVaInCodeSection(LPVOID lpvPosition);
			/// <summary>
			/// 获取代码节中的空闲的区域
			/// </summary>
			/// <param name="dwSize">空闲区域的最小的大小</param>
			/// <returns>pair(起始地址，结束地址)</returns>
			MYOBJECT_API std::pair<LPVOID, LPVOID> m_GetFreeCodeLocation(DWORD dwSize = 0);
			/// <summary>
			/// 获取所有节中空闲区域的地址，并将该节修改为可执行
			/// </summary>
			/// <param name="ppSectionHeader">空闲的节的节表的地址</param>
			/// <param name="dwSize">空闲区域的最小的大小</param>
			/// <returns>pair(起始地址，结束地址)</returns>
			MYOBJECT_API std::pair<LPVOID, LPVOID> m_GetFreeLocation(PIMAGE_SECTION_HEADER* ppSectionHeader, DWORD dwSize = 0);
			/// <summary>
			/// 获取指定中空闲区域的地址，并将该节修改为可执行
			/// </summary>
			/// <param name="ppSectionHeader">空闲的节的节表的地址</param>
			/// <param name="dwSize">空闲区域的最小的大小</param>
			/// <param name="dwNumOfSection">第几个节</param>
			/// <returns>pair(起始地址，结束地址)</returns>
			MYOBJECT_API std::pair<LPVOID, LPVOID> m_GetFreeLocation(PIMAGE_SECTION_HEADER* ppSectionHeader, DWORD dwSize , DWORD dwNumOfSection );
#endif
#if 1 
		/// <summary>
		/// 添加新的节
		/// </summary>
		public:
			/// <summary>
			/// 读取pFileBuffer处的PE文件，新增长度为dwSize的节 将新增的pe文件放入_lpvFileAddSection中
			/// </summary>
			/// <param name="pFileBuffer">原始PE文件内存地址</param>
			/// <param name="dwFileSize">原始PE文件长度</param>
			/// <param name="dwSize">新增节的长度</param>
			///<param name="dwSize">新增节的长度</param>
			///<param name="dwCharacteristics">新增节的属性</param>
			///<param name="abName">新增节的名字</param>
			///<param name="lpvShellcode">新增节的非空白内容</param>
			/// <returns>是否成功</returns>
			template <size_t N>
			MYOBJECT_API PVOID FileAddAnNewSection(IN LPVOID pFileBuffer, IN DWORD dwFileSize, IN DWORD dwSize, IN DWORD dwCharacteristics, IN const BYTE(&abName)[8], IN BYTE(&lpvShellcode)[N]);

			//以下操作需要新增节之后再进行*************

			/// <summary>
			/// 返回添加节后文件映像的地址
			/// </summary>
			/// <returns>返回地址</returns>
			MYOBJECT_API LPVOID GetlpAddNewSection() noexcept { return _lpvFileAddSection; }

			/// <summary>
			/// 移动导出表到固定地址
			/// </summary>
			/// <param name="pvPosition">要移动过的地址</param>
			/// <param name="vecExport">导出表数据结构</param>
			/// <returns></returns>
			MYOBJECT_API PVOID MoveTheExportTable(PVOID pvPosition, vecExports& vecExport);
			/// <summary>
			/// 移动重定位表
			/// </summary>
			/// <param name="pvPosition">移动重定位表的地址</param>
			/// <param name="vecRelocs">重定位表结构体</param>
			/// <returns></returns>
			MYOBJECT_API PVOID MoveTheRelocTable(PVOID pvPosition, vecReloc& vecRelocs);

			/// <summary>
			/// 导入表注入
			/// </summary>
			/// <param name="pvPosition">写入的新的节的地址</param>
			/// <param name="szInjectDllName">导入的DLL的名字</param>
			/// <param name="szInjectDllFuncName">注入至少需要一个导入的函数名</param>
			/// <returns>返回剩余空闲地址</returns>
			MYOBJECT_API PVOID ImportInject(PVOID pvPosition, PCSTR szInjectDllName, PCSTR szInjectDllFuncName);
		private:
			/// <summary>
			/// 判断是否又足够的区域添加一个节表
			/// </summary>
			/// <param name="lpvMemPosition">PE文件起始地址</param>
			/// <returns>能否</returns>
			MYOBJECT_API BOOL IsThereenoughTpaceToAddSectionTables(LPVOID lpvMemPosition);
			/// <summary>
			/// 获取地址添加新的节表
			/// </summary>
			/// <param name="lpvMemPosition">PE文件起始地址</param>
			/// <returns>能否</returns>
			MYOBJECT_API LPVOID GetMorePositon(LPVOID lpvMemPosition);
			/// <summary>
			/// PE文件拷贝到一个新的位置，扩大文件大小
			/// </summary>
			/// <param name="pFileBuffer">原始PE文件的地址</param>
			/// <param name="dwFileSize">原始PE文件大小</param>
			/// <param name="pImageBuffer">新的地址空间</param>
			/// <param name="dwSize">新增的大小</param>
			/// <returns>错误码</returns>
			MYOBJECT_API DWORD GetFileBufferWithAnNewSection( LPVOID pFileBuffer, DWORD dwFileSize, LPVOID* pImageBuffer,  DWORD dwSize);
			/// <summary>
			/// 添加一个新的节
			/// </summary>
			/// <param name="lpvMemPosition">已经分配好空间的地址</param>
			/// <param name="dwRawSize">扩大的文件大小</param>
			/// <param name="dwVirtualSize">添加的实际大小</param>
			/// <param name="dwCharacteristics">属性</param>
			/// <param name="abName">节名</param>
			/// <returns>新增节的文件偏移</returns>
			MYOBJECT_API PVOID AddTheSection(LPVOID lpvMemPosition, DWORD dwRawSize, DWORD dwVirtualSize, DWORD dwCharacteristics, const BYTE(&abName)[8]);
			/// <summary>
			/// 添加一个节表
			/// </summary>
			/// <param name="pSectionHeader">添加节表的起始位置</param>
			/// <param name="dwRawSize">文件映像的大小</param>
			/// <param name="dwVirtualSize">虚拟映像的大小</param>
			/// <param name="dwCharacteristics">属性</param>
			/// <param name="abName">文件名</param>
			/// <returns>返回新增节的文件偏移</returns>
			MYOBJECT_API PVOID AddTheSectionTable(PIMAGE_SECTION_HEADER pSectionHeader, DWORD dwRawSize, DWORD dwVirtualSize, DWORD dwCharacteristics, const  BYTE(&abName)[8]);
#endif	//添加新的节
#if 1
		public:
			/// <summary>
			/// 扩大已读取映像的最后一个节 
			/// </summary>
			/// <param name="dwSize">扩大的大小</param>
			/// <param name="dwVirtualSize">扩大的虚拟大小</param>
			/// <returns>是否成功</returns>
			MYOBJECT_API bool ExpandLastSection(DWORD dwSize, DWORD dwVirtualSize = 0);
#endif //扩大最后一个节
#if 1
		public:
			/// <summary>
			/// 合并所有其他节
			/// </summary>
			/// <returns></returns>
			MYOBJECT_API bool MergeAllSections();
#endif	//将所有节合并

		private:
			LPVOID _lpvFilePosition ;//原始文件镜像内存位置
			LPVOID _lpvMemPosition ;//原始内存镜像内存位置

			TransFileAndMem& _tf;

			LPVOID _lpvFileAddSection = NULL;//添加节的文件镜像内存位置

			LPVOID _lpvMemMergeLastSection = NULL;//扩大最后一个节的内存镜像位置
			LPVOID _lpvFileMergeLastSection = NULL;//扩大最后一个节的文件映像镜像位置

			bool _isPe32;//是否是32位文件
		};

		template<size_t N>
		BOOL PEChange::CopyShellCode(BYTE(&abShellocod)[N], LPVOID lpAddress)
		{
			PBYTE pbAddress = (PBYTE)lpAddress;
			for (int i = 0; i < N; i++)
			{
				if (*pbAddress == 0x00)
				{
					continue;
				}
				else
					return false; //内存非空白区
			}
			memcpy_s(lpAddress, N, abShellocod, N);
			return true;
		}

		template <size_t N>
		MYOBJECT_API PVOID PEChange::FileAddAnNewSection(IN LPVOID pFileBuffer, IN DWORD dwFileSize, IN DWORD dwSize, IN DWORD dwCharacteristics, IN const BYTE(&abName)[8], IN BYTE(&lpvShellcode)[N])
		{
			LPVOID lpNewFileBuffer = NULL;
			PVOID pvPositon = NULL;
			__try
			{
				DWORD dwError = GetFileBufferWithAnNewSection(pFileBuffer, dwFileSize, &lpNewFileBuffer, dwSize);
				if (lpNewFileBuffer == NULL)
				{
#if _DEBUG
					printf("为PE文件申请内存失败 ErrorCode = %d\r\n", dwError);
#endif
					pvPositon = NULL;
					__leave;
				}


				if (!(pvPositon = AddTheSection(lpNewFileBuffer, dwSize, dwSize, dwCharacteristics, abName)))
				{
#if _DEBUG
					printf("没有足够的空间容纳新的节表\r\n");
#endif
					pvPositon = NULL;
					__leave;
				}

				if (N!=0)
				{

				}
				else
				{

				}
				if (!_tf.MemeryTOFile(lpNewFileBuffer, dwFileSize + dwSize, TEXT("newPeFile.exe")))
				{
#if _DEBUG
					printf("写回文件失败\r\n");
#endif
					pvPositon = NULL;
					__leave;
				}

				_lpvFileAddSection = lpNewFileBuffer;
				pvPositon = (PVOID)(DWORD(pvPositon) + (DWORD)_lpvFileAddSection);

				if (_tf._lpvNewFilePosition)
					VirtualFree(_tf._lpvNewFilePosition, 0, MEM_RELEASE);
				_tf._lpvNewFilePosition = _lpvFileAddSection;
				_tf._uNewSize = dwFileSize + dwSize;
			}
			__finally
			{
				if (lpNewFileBuffer != NULL && !pvPositon)
					VirtualFree(lpNewFileBuffer, 0, MEM_RELEASE);
			}

			return pvPositon;
		}
		/// <summary>
		/// 测试程序
		/// </summary>
		/// <param name="tfam">pe转换类</param>
		/// <param name="pe">pe识别类</param>
		/// <returns></returns>
		void InsertShelloCode(TransFileAndMem& tfam, PEImage& pe);


}
}