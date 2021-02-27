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
/// �����еĿ����������
/// </summary>
			
			/// <summary>
			/// ��ȡҪe8 ���� e9�ĵ�ַ�����ƫ��
			/// </summary>
			/// <param name="lpvAddress">Ҫ���õĵ�ַ</param>
			/// <param name="lpvPosition">�ڴ�����Ļ�ַ</param>
			/// <param name="dwPianYi">�ڴ������ƫ��</param>
			/// <returns>ת���õ�ƫ��</returns>
			MYOBJECT_API LPVOID GetCallAddress(LPVOID lpvAddress,LPVOID lpvPosition,DWORD dwPianYi = 0);
			/// <summary>
			/// ��ȡ�հ״�������
			/// </summary>
			/// <param name="dwSize">�հ��������С�Ĵ�С</param>
			/// <returns>�հ���ʼλ��λ�úͽ���λ��</returns>
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
			/// ��ȡָ���ڵĿհ�λ�� ��������Ϊ��ִ��
			/// </summary>
			/// <param name="dwSize">��С�Ĵ�С</param>
			/// <param name="dwNumOfSection">�ڼ�����</param>
			/// <returns>�հ���ʼλ��λ�úͽ���λ��</returns>
			MYOBJECT_API std::pair<LPVOID, LPVOID> GetFreeLocation(DWORD dwSize, DWORD dwNumOfSection )
			{
				PIMAGE_SECTION_HEADER pSectionHeader = NULL;
				auto ret = m_GetFreeLocation(&pSectionHeader, dwSize,dwNumOfSection);
				if(pSectionHeader != NULL)									//����������пհ׵�ַ����
					pSectionHeader->Characteristics |= IMAGE_SCN_CNT_CODE|IMAGE_SCN_MEM_EXECUTE;//������ִ������
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
			/// ��ȡ���нڵĿ��ܿհ�λ�� ��������Ϊ��ִ��
			/// </summary>
			/// <param name="dwSize">��С�Ĵ�С</param>
			/// <returns>�հ���ʼλ��λ�úͽ���λ��</returns>
			MYOBJECT_API std::pair<LPVOID, LPVOID> GetFreeLocation(DWORD dwSize = 0)
			{
				PIMAGE_SECTION_HEADER pSectionHeader = NULL;
				auto ret = m_GetFreeLocation(&pSectionHeader,dwSize);
				if (pSectionHeader != NULL)									//����������пհ׵�ַ����
					pSectionHeader->Characteristics |= IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE;//������ִ������
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
			/// ��ope����Ϊ������Ҫ�ĵ�ַ
			/// </summary>
			/// <param name="lpvAddress">��Ҫ����Ϊ�ĵ�ַ</param>
			/// <returns>��</returns>
			MYOBJECT_API inline void FixOep(LPVOID lpvAddress)
			{
				if (_isPe32)
				{
					PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvMemPosition;//dosͷ
					PIMAGE_NT_HEADERS pNtHeader = NULL;//ntͷ
					pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
					pNtHeader->OptionalHeader.AddressOfEntryPoint = (DWORD)lpvAddress - (DWORD)_lpvMemPosition;
				}
			}
			/// <summary>
			/// ����shellcode
			/// </summary>
			/// <param name="abShellocod">shellcode����</param>
			/// <param name="lpAddress">�������ĵ�ַ</param>
			/// <returns>�Ƿ�ɹ�</returns>
			MYOBJECT_API template<size_t N>
			BOOL CopyShellCode(BYTE(&abShellocod)[N], LPVOID lpAddress);
		private:
			/// <summary>
			/// ��ȡ�����ַ����ʵ�ڴ�ӳ��ĵ�ַ
			/// </summary>
			/// <param name="lpvPosition">���ǵ���_lpvMemPosition��ͷ��PE�ļ���VA</param>
			/// <returns>��ַ</returns>
			MYOBJECT_API LPVOID m_GetVaInCodeSection(LPVOID lpvPosition);
			/// <summary>
			/// ��ȡ������еĿ��е�����
			/// </summary>
			/// <param name="dwSize">�����������С�Ĵ�С</param>
			/// <returns>pair(��ʼ��ַ��������ַ)</returns>
			MYOBJECT_API std::pair<LPVOID, LPVOID> m_GetFreeCodeLocation(DWORD dwSize = 0);
			/// <summary>
			/// ��ȡ���н��п�������ĵ�ַ�������ý��޸�Ϊ��ִ��
			/// </summary>
			/// <param name="ppSectionHeader">���еĽڵĽڱ�ĵ�ַ</param>
			/// <param name="dwSize">�����������С�Ĵ�С</param>
			/// <returns>pair(��ʼ��ַ��������ַ)</returns>
			MYOBJECT_API std::pair<LPVOID, LPVOID> m_GetFreeLocation(PIMAGE_SECTION_HEADER* ppSectionHeader, DWORD dwSize = 0);
			/// <summary>
			/// ��ȡָ���п�������ĵ�ַ�������ý��޸�Ϊ��ִ��
			/// </summary>
			/// <param name="ppSectionHeader">���еĽڵĽڱ�ĵ�ַ</param>
			/// <param name="dwSize">�����������С�Ĵ�С</param>
			/// <param name="dwNumOfSection">�ڼ�����</param>
			/// <returns>pair(��ʼ��ַ��������ַ)</returns>
			MYOBJECT_API std::pair<LPVOID, LPVOID> m_GetFreeLocation(PIMAGE_SECTION_HEADER* ppSectionHeader, DWORD dwSize , DWORD dwNumOfSection );
#endif
#if 1 
		/// <summary>
		/// ����µĽ�
		/// </summary>
		public:
			/// <summary>
			/// ��ȡpFileBuffer����PE�ļ�����������ΪdwSize�Ľ� ��������pe�ļ�����_lpvFileAddSection��
			/// </summary>
			/// <param name="pFileBuffer">ԭʼPE�ļ��ڴ��ַ</param>
			/// <param name="dwFileSize">ԭʼPE�ļ�����</param>
			/// <param name="dwSize">�����ڵĳ���</param>
			///<param name="dwSize">�����ڵĳ���</param>
			///<param name="dwCharacteristics">�����ڵ�����</param>
			///<param name="abName">�����ڵ�����</param>
			///<param name="lpvShellcode">�����ڵķǿհ�����</param>
			/// <returns>�Ƿ�ɹ�</returns>
			template <size_t N>
			MYOBJECT_API PVOID FileAddAnNewSection(IN LPVOID pFileBuffer, IN DWORD dwFileSize, IN DWORD dwSize, IN DWORD dwCharacteristics, IN const BYTE(&abName)[8], IN BYTE(&lpvShellcode)[N]);

			//���²�����Ҫ������֮���ٽ���*************

			/// <summary>
			/// ������ӽں��ļ�ӳ��ĵ�ַ
			/// </summary>
			/// <returns>���ص�ַ</returns>
			MYOBJECT_API LPVOID GetlpAddNewSection() noexcept { return _lpvFileAddSection; }

			/// <summary>
			/// �ƶ��������̶���ַ
			/// </summary>
			/// <param name="pvPosition">Ҫ�ƶ����ĵ�ַ</param>
			/// <param name="vecExport">���������ݽṹ</param>
			/// <returns></returns>
			MYOBJECT_API PVOID MoveTheExportTable(PVOID pvPosition, vecExports& vecExport);
			/// <summary>
			/// �ƶ��ض�λ��
			/// </summary>
			/// <param name="pvPosition">�ƶ��ض�λ��ĵ�ַ</param>
			/// <param name="vecRelocs">�ض�λ��ṹ��</param>
			/// <returns></returns>
			MYOBJECT_API PVOID MoveTheRelocTable(PVOID pvPosition, vecReloc& vecRelocs);

			/// <summary>
			/// �����ע��
			/// </summary>
			/// <param name="pvPosition">д����µĽڵĵ�ַ</param>
			/// <param name="szInjectDllName">�����DLL������</param>
			/// <param name="szInjectDllFuncName">ע��������Ҫһ������ĺ�����</param>
			/// <returns>����ʣ����е�ַ</returns>
			MYOBJECT_API PVOID ImportInject(PVOID pvPosition, PCSTR szInjectDllName, PCSTR szInjectDllFuncName);
		private:
			/// <summary>
			/// �ж��Ƿ����㹻���������һ���ڱ�
			/// </summary>
			/// <param name="lpvMemPosition">PE�ļ���ʼ��ַ</param>
			/// <returns>�ܷ�</returns>
			MYOBJECT_API BOOL IsThereenoughTpaceToAddSectionTables(LPVOID lpvMemPosition);
			/// <summary>
			/// ��ȡ��ַ����µĽڱ�
			/// </summary>
			/// <param name="lpvMemPosition">PE�ļ���ʼ��ַ</param>
			/// <returns>�ܷ�</returns>
			MYOBJECT_API LPVOID GetMorePositon(LPVOID lpvMemPosition);
			/// <summary>
			/// PE�ļ�������һ���µ�λ�ã������ļ���С
			/// </summary>
			/// <param name="pFileBuffer">ԭʼPE�ļ��ĵ�ַ</param>
			/// <param name="dwFileSize">ԭʼPE�ļ���С</param>
			/// <param name="pImageBuffer">�µĵ�ַ�ռ�</param>
			/// <param name="dwSize">�����Ĵ�С</param>
			/// <returns>������</returns>
			MYOBJECT_API DWORD GetFileBufferWithAnNewSection( LPVOID pFileBuffer, DWORD dwFileSize, LPVOID* pImageBuffer,  DWORD dwSize);
			/// <summary>
			/// ���һ���µĽ�
			/// </summary>
			/// <param name="lpvMemPosition">�Ѿ�����ÿռ�ĵ�ַ</param>
			/// <param name="dwRawSize">������ļ���С</param>
			/// <param name="dwVirtualSize">��ӵ�ʵ�ʴ�С</param>
			/// <param name="dwCharacteristics">����</param>
			/// <param name="abName">����</param>
			/// <returns>�����ڵ��ļ�ƫ��</returns>
			MYOBJECT_API PVOID AddTheSection(LPVOID lpvMemPosition, DWORD dwRawSize, DWORD dwVirtualSize, DWORD dwCharacteristics, const BYTE(&abName)[8]);
			/// <summary>
			/// ���һ���ڱ�
			/// </summary>
			/// <param name="pSectionHeader">��ӽڱ����ʼλ��</param>
			/// <param name="dwRawSize">�ļ�ӳ��Ĵ�С</param>
			/// <param name="dwVirtualSize">����ӳ��Ĵ�С</param>
			/// <param name="dwCharacteristics">����</param>
			/// <param name="abName">�ļ���</param>
			/// <returns>���������ڵ��ļ�ƫ��</returns>
			MYOBJECT_API PVOID AddTheSectionTable(PIMAGE_SECTION_HEADER pSectionHeader, DWORD dwRawSize, DWORD dwVirtualSize, DWORD dwCharacteristics, const  BYTE(&abName)[8]);
#endif	//����µĽ�
#if 1
		public:
			/// <summary>
			/// �����Ѷ�ȡӳ������һ���� 
			/// </summary>
			/// <param name="dwSize">����Ĵ�С</param>
			/// <param name="dwVirtualSize">����������С</param>
			/// <returns>�Ƿ�ɹ�</returns>
			MYOBJECT_API bool ExpandLastSection(DWORD dwSize, DWORD dwVirtualSize = 0);
#endif //�������һ����
#if 1
		public:
			/// <summary>
			/// �ϲ�����������
			/// </summary>
			/// <returns></returns>
			MYOBJECT_API bool MergeAllSections();
#endif	//�����нںϲ�

		private:
			LPVOID _lpvFilePosition ;//ԭʼ�ļ������ڴ�λ��
			LPVOID _lpvMemPosition ;//ԭʼ�ڴ澵���ڴ�λ��

			TransFileAndMem& _tf;

			LPVOID _lpvFileAddSection = NULL;//��ӽڵ��ļ������ڴ�λ��

			LPVOID _lpvMemMergeLastSection = NULL;//�������һ���ڵ��ڴ澵��λ��
			LPVOID _lpvFileMergeLastSection = NULL;//�������һ���ڵ��ļ�ӳ����λ��

			bool _isPe32;//�Ƿ���32λ�ļ�
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
					return false; //�ڴ�ǿհ���
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
					printf("ΪPE�ļ������ڴ�ʧ�� ErrorCode = %d\r\n", dwError);
#endif
					pvPositon = NULL;
					__leave;
				}


				if (!(pvPositon = AddTheSection(lpNewFileBuffer, dwSize, dwSize, dwCharacteristics, abName)))
				{
#if _DEBUG
					printf("û���㹻�Ŀռ������µĽڱ�\r\n");
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
					printf("д���ļ�ʧ��\r\n");
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
		/// ���Գ���
		/// </summary>
		/// <param name="tfam">peת����</param>
		/// <param name="pe">peʶ����</param>
		/// <returns></returns>
		void InsertShelloCode(TransFileAndMem& tfam, PEImage& pe);


}
}