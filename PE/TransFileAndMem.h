#pragma once
#include "../Config.h"
#include "../Include/Winheaders.h"
#include "../Include/Type.h"
#include "PEImage.h"
namespace MyObject
{
	namespace pe
	{
		class TransFileAndMem
		{
			friend class PEChange;
			using PCHDR32 = const IMAGE_NT_HEADERS32*;
			using PCHDR64 = const IMAGE_NT_HEADERS64*;

		public:
			MYOBJECT_API TransFileAndMem() = default;
			/// <summary>
			/// 构造函数 初始化某些参数
			/// </summary>
			/// <param name="lpvFilePosition">PE文件映像的起始地址</param>
			/// <param name="uSize">输入的PE文件映像文件大小</param>
			/// <param name="bIsWin32">输入的文件是否是32位PE文件</param>
			MYOBJECT_API TransFileAndMem(LPVOID lpvFilePosition, uint32_t uSize, bool bIsWin32 = true) :
				_lpvOldFilePosition(lpvFilePosition), _uOldSize(uSize), _bFileIs32(bIsWin32), _bFileNew(false){}
			/// <summary>
			/// 析构函数 释放处理需要的申请的内存
			/// </summary>
			MYOBJECT_API ~TransFileAndMem()
			{
				if (_lpvNewFilePosition != NULL)
					VirtualFree(_lpvNewFilePosition, 0, MEM_RELEASE);
				if (_lpvNewMemPosition != NULL)
					VirtualFree(_lpvNewMemPosition, 0, MEM_RELEASE);
			}
			/// <summary>
			/// 设置输入文件的长度
			/// </summary>
			/// <param name="size">需要设置的长度</param>
			MYOBJECT_API void inline SetSize(uint32_t size) { _uOldSize = size; }
			/// <summary>
			/// 重写输入文件映像的地址
			/// </summary>
			/// <param name="size">需要设置的长度</param>
			MYOBJECT_API void inline SetAddress(LPVOID lpvFilePosition) { _lpvOldFilePosition = lpvFilePosition; _bFileNew = true; }
			/// <summary>
			/// 文件映像拉伸位内存映像
			/// </summary>
			/// <returns>Status code</returns>
			MYOBJECT_API NTSTATUS inline transformFileToImage() {
				if (_lpvNewMemPosition != NULL)
				{
					VirtualFree(_lpvNewMemPosition, 0, MEM_RELEASE);
					_lpvNewMemPosition = NULL;
				}
				if (_bFileIs32)
					return CopyFileBufferToImageBuffer(_lpvOldFilePosition, &_lpvNewMemPosition);
				else
					return CopyFileBufferToImageBuffer_X64(_lpvOldFilePosition, &_lpvNewMemPosition);
			}
			/// <summary>
			/// 内存映像还原为文件映像
			/// </summary>
			/// <param name="size">需要设置的长度</param>
			/// <param name="skipActx">If true - do not initialize activation context</param>
			/// <returns>Status code</returns>
			MYOBJECT_API void inline transformImageToFile() {
				if (_lpvNewFilePosition)
				{
					VirtualFree(_lpvNewFilePosition, 0, MEM_RELEASE);
					_lpvNewFilePosition = NULL;
				}

				if (_bFileIs32)
				{
					_uNewSize = CopyImageBufferToNewBuffer(_lpvNewMemPosition, &_lpvNewFilePosition);
				}
				else
					_uNewSize = CopyImageBufferToNewBuffer_X64(_lpvNewMemPosition, &_lpvNewFilePosition);
			}
			/// <summary>
			/// 内存映像还原为文件映像
			/// </summary>
			/// <param name="size">需要设置的长度</param>
			/// <param name="skipActx">If true - do not initialize activation context</param>
			/// <returns>Status code</returns>
			MYOBJECT_API BOOL inline writeBackNewFile(IN LPCTSTR lpszFile) {
				if (_uNewSize == 0)
					_uNewSize = _uOldSize;
				return MemeryTOFile(_lpvNewFilePosition, _uNewSize, lpszFile);
			}
			MYOBJECT_API BOOL inline writeBackOldFile(IN LPCTSTR lpszFile) {
				return MemeryTOFile(_lpvOldFilePosition, _uOldSize, lpszFile);
			}
			MYOBJECT_API LPVOID inline m_Position_RvatoFile(LPVOID lpvRva) {
				if (_bFileIs32)
				{
					return LPVOID((DWORD)_lpvNewFilePosition +RvaToFoa(_lpvNewMemPosition, (DWORD)lpvRva));
				}
			}
			MYOBJECT_API LPVOID inline m_Position_FoatoImage(LPVOID lpvFoa) {
				if (_bFileIs32)
				{
					return LPVOID((DWORD)_lpvNewMemPosition + FoaToRva(_lpvNewFilePosition, (DWORD)lpvFoa));
				}
			}
			MYOBJECT_API LPVOID inline m_Position_FiletoImage(LPVOID lpAddress) {
				if (_bFileIs32)
				{
					DWORD dwFoa = (DWORD)lpAddress - (DWORD)_lpvNewFilePosition;
					return m_Position_FoatoImage((LPVOID)dwFoa);
				}
			}
			MYOBJECT_API LPVOID inline m_Position_ImagetoFile(LPVOID lpAddress) {
				if (_bFileIs32)
				{
					DWORD dwRva = (DWORD)lpAddress - (DWORD)_lpvNewMemPosition;
					return m_Position_RvatoFile((LPVOID)dwRva);
				}
			}
			/// <summary>
			/// 获取PE文件的大小
			/// </summary>
			/// <param name="pImageBuffer"></param>
			/// <returns>PE文件的长度</returns>
			MYOBJECT_API DWORD m_GetFileSize(LPCVOID pImageBuffer) noexcept;
			MYOBJECT_API DWORD FixTheImageBase(DWORD dwImageBase, vecReloc& vecReloc);
		private:
			uint32_t _uOldSize;
			uint32_t _uNewSize = 0;

			LPVOID _lpvOldFilePosition;
			LPVOID _lpvNewFilePosition = NULL;
			LPVOID _lpvNewMemPosition = NULL;

			bool _bFileNew = false;
			bool _bFileIs32;

		private :
			MYOBJECT_API NTSTATUS CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer);
			MYOBJECT_API NTSTATUS CopyFileBufferToImageBuffer_X64(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer);

			MYOBJECT_API DWORD CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer);
			MYOBJECT_API ULONG_PTR CopyImageBufferToNewBuffer_X64(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer);

			MYOBJECT_API BOOL MemeryTOFile(IN LPVOID pMemBuffer, IN size_t size, IN LPCTSTR lpszFile);
			MYOBJECT_API BOOL MemeryTOFile64(IN LPVOID pMemBuffer, IN size_t size, IN size_t size_h, IN LPCTSTR lpszFile);

			MYOBJECT_API DWORD RvaToFoa(IN PVOID lpvImageBuffer, IN DWORD dwRva);
			MYOBJECT_API DWORD FoaToRva(IN LPVOID lpvFileBuffer, IN DWORD dwRva);

		};
	}
}


