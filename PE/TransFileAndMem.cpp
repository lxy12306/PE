#include "TransFileAndMem.h"
#include "../Include/Macro.h"
#include "../Misc/Utils.h"
namespace MyObject
{
namespace pe
{
    MYOBJECT_API NTSTATUS TransFileAndMem::CopyFileBufferToImageBuffer(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer)
    {
        _IMAGE_DOS_HEADER* pDosHeader;//dos头
        PCHDR32 pNtHeader;//nt头
    
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
        pNtHeader = (PCHDR32)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        {
#if _DEBUG
            printf("读取的文件不是标准PE文件");
#endif
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    
        //节表位置
        dSectionPosition = (DWORD)pFileBuffer + pDosHeader->e_lfanew + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) + pNtHeader->FileHeader.SizeOfOptionalHeader;
        //sizeof(DWORD)为+00h    DWORD Signature; // 固定为 0x00004550  根据小端存储为："PE.."的大小
    
        //节表
        PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)dSectionPosition;
    
        //分配内存
        *pImageBuffer = VirtualAlloc(NULL, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//SizeOfImage:当镜像被加载进内存时的大小，包括所有的文件头。向上舍入为SectionAlignment的倍数; 一般文件大小与加载到内存中的大小是不同的。 -> 00 00 50 00'
        if (*pImageBuffer == NULL)
        {
#if _DEBUG
            printf("VirtualAlloc filed error=%d", GetLastError());
#endif
            return LastNtStatus();
        }
        memset(*pImageBuffer, 0, pNtHeader->OptionalHeader.SizeOfImage);
        //写入header 包括dos头 pe头 节表
        __try
        {
            memcpy(*pImageBuffer, pFileBuffer, pNtHeader->OptionalHeader.SizeOfHeaders);

            //遍历节表
            size_t nNum = pNtHeader->FileHeader.NumberOfSections;
            while (nNum--)
            {
                memcpy(PVOID((DWORD)*pImageBuffer + (pSectionHeader)->VirtualAddress), PVOID((DWORD)pFileBuffer + (pSectionHeader)->PointerToRawData), pSectionHeader->SizeOfRawData);
                pSectionHeader++;
            }
            return pNtHeader->OptionalHeader.SizeOfImage;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
#if _DEBUG
            printf("memcpy filed error");
#endif
            return  LastNtStatus();
        }
        return STATUS_SUCCESS;
    }
    MYOBJECT_API NTSTATUS TransFileAndMem::CopyFileBufferToImageBuffer_X64(IN LPVOID pFileBuffer, OUT LPVOID* pImageBuffer)
    {
        //dos头
        _IMAGE_DOS_HEADER* pDosHeader;//dos头
        PCHDR64 pNtHeader;//nt头

        uint64_t dSectionPosition;

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
        pNtHeader = (PCHDR64)((uint64_t)pFileBuffer + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        {
#if _DEBUG
            printf("读取的文件不是标准PE文件");
#endif
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        //节表位置
        dSectionPosition = (uint64_t)pFileBuffer + pDosHeader->e_lfanew + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) + pNtHeader->FileHeader.SizeOfOptionalHeader;
        //sizeof(DWORD)为+00h    DWORD Signature; // 固定为 0x00004550  根据小端存储为："PE.."的大小

        //节表
        PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)dSectionPosition;

        //分配内存
        *pImageBuffer = VirtualAlloc(NULL, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//SizeOfImage:当镜像被加载进内存时的大小，包括所有的文件头。向上舍入为SectionAlignment的倍数; 一般文件大小与加载到内存中的大小是不同的。 -> 00 00 50 00'
        if (*pImageBuffer == NULL)
        {
#if _DEBUG
            printf("VirtualAlloc filed error=%d", GetLastError());
#endif
            return LastNtStatus();
        }
        memset(*pImageBuffer, 0, pNtHeader->OptionalHeader.SizeOfImage);
        //写入header 包括dos头 pe头 节表
        __try
        {
            memcpy(*pImageBuffer, pFileBuffer, pNtHeader->OptionalHeader.SizeOfHeaders);

            //遍历节表
            size_t nNum = pNtHeader->FileHeader.NumberOfSections;
            while (nNum--)
            {
                memcpy(PVOID((uint64_t)*pImageBuffer + (pSectionHeader)->VirtualAddress), PVOID((uint64_t)pFileBuffer + (pSectionHeader)->PointerToRawData), pSectionHeader->SizeOfRawData);
                pSectionHeader++;
            }
            return pNtHeader->OptionalHeader.SizeOfImage;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
#if _DEBUG
            printf("memcpy filed error");
#endif
            return  LastNtStatus();
        }
        return STATUS_SUCCESS;
    }
    MYOBJECT_API DWORD TransFileAndMem::CopyImageBufferToNewBuffer(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer)
    {
        _IMAGE_DOS_HEADER* pDosHeader;//dos头
        PCHDR32 pNtHeader;
        DWORD dwSetionPosition;
        pDosHeader = (_IMAGE_DOS_HEADER*)pImageBuffer;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
#if _DEBUG
            printf("内存缓冲区的文件格式有问题");
#endif
            return -1;
        }

        pNtHeader = (_IMAGE_NT_HEADERS*)((DWORD)pImageBuffer + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        {
#if _DEBUG
            printf("内存缓冲区的文件格式有问题");
#endif
            return -1;
        }

        dwSetionPosition = (DWORD)pImageBuffer + pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(_IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader;

        //节表
        PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)dwSetionPosition;
        //找到最后一个节表
        PIMAGE_SECTION_HEADER pLastSetion = (PIMAGE_SECTION_HEADER)(pSectionHeader + pNtHeader->FileHeader.NumberOfSections - 1);

        size_t fileSize = pLastSetion->PointerToRawData + pLastSetion->SizeOfRawData;
        /*最后一个节的位置+长度 为最后的磁盘文件的长度*/


        *pNewBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//申请内存
        if (*pNewBuffer == NULL)
        {
#if _DEBUG
            printf("VirtualAlloc filed error=%d", GetLastError());
#endif
            return -1;
        }
        memset(*pNewBuffer, 0, fileSize);

        //复制头信息
        memcpy(*pNewBuffer, pImageBuffer, pNtHeader->OptionalHeader.SizeOfHeaders);

        size_t nNum = pNtHeader->FileHeader.NumberOfSections;
        //遍历节表
        while (nNum--)
        {
            memcpy(PVOID((DWORD)*pNewBuffer + (pSectionHeader)->PointerToRawData), PVOID((DWORD)pImageBuffer + (pSectionHeader)->VirtualAddress), pSectionHeader->SizeOfRawData);
            pSectionHeader++;
        }

        return fileSize;
    }
    MYOBJECT_API ULONG_PTR TransFileAndMem::CopyImageBufferToNewBuffer_X64(IN LPVOID pImageBuffer, OUT LPVOID* pNewBuffer)
    {
        _IMAGE_DOS_HEADER* pDosHeader;//dos头
        PCHDR64 pNtHeader;
        ULONG_PTR setionPosition;
        pDosHeader = (_IMAGE_DOS_HEADER*)pImageBuffer;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
#if _DEBUG
            printf("内存缓冲区的文件格式有问题");
#endif
            return -1;
        }

        pNtHeader = (PCHDR64)((ULONG_PTR)pImageBuffer + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        {
#if _DEBUG
            printf("内存缓冲区的文件格式有问题");
#endif
            return -1;
        }

        setionPosition = (ULONG_PTR)pImageBuffer + pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(_IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader;

        //节表
        PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)setionPosition;
        //找到最后一个节表
        PIMAGE_SECTION_HEADER pLastSetion = (PIMAGE_SECTION_HEADER)(pSectionHeader + pNtHeader->FileHeader.NumberOfSections - 1);

        size_t fileSize = pLastSetion->PointerToRawData + pLastSetion->SizeOfRawData;
        /*最后一个节的位置+长度 为最后的磁盘文件的长度*/


        *pNewBuffer = VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);//生气内存
        if (*pNewBuffer == NULL)
        {
            printf("VirtualAlloc filed error=%d", GetLastError());
            return -1;
        }
        memset(*pNewBuffer, 0, fileSize);

        //复制头信息
        memcpy(*pNewBuffer, pImageBuffer, pNtHeader->OptionalHeader.SizeOfHeaders);

        size_t nNum = pNtHeader->FileHeader.NumberOfSections;
        //遍历节表
        while (nNum--)
        {
            memcpy(PVOID((ULONG_PTR)*pNewBuffer + (pSectionHeader)->PointerToRawData), PVOID((ULONG_PTR)pImageBuffer + (pSectionHeader)->VirtualAddress), pSectionHeader->SizeOfRawData);
            pSectionHeader++;
        }

        return fileSize;
    }
    MYOBJECT_API DWORD TransFileAndMem::RvaToFoa(IN PVOID lpvImageBuffer, IN DWORD dwRva)
    {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpvImageBuffer;//dos头
        PCHDR32  pNtHeader = NULL;//nt头

        //dos头
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
#if _DEBUG
            printf("(RVA转换成FOA阶段)读取的文件不是标准PE文件\r\n");
#endif
            return -1;
        }

        //NT头
        pNtHeader = (PCHDR32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        {
#if _DEBUG
            printf("(RVA转换成FOA阶段)读取的文件不是标准PE文件\r\n");
#endif
            return -1;
        }

        PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader+ pNtHeader->FileHeader.SizeOfOptionalHeader+ IMAGE_SIZEOF_FILE_HEADER +sizeof(DWORD));

        for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i, ++pSectionHeader)
        {	//判断 :  Misc.VirtualSize+ VirtualAddress 内存偏移+节数据没对齐的大小>image_panyi>内存偏移 VirtualAddress (即是在文件的哪个节中)
            if ((dwRva >= pSectionHeader->VirtualAddress) && (dwRva < pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize))
            {

                return dwRva - pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
            }
        }
        
        if (dwRva <= ((DWORD)pSectionHeader - (DWORD)lpvImageBuffer))
        {
            return dwRva;
        }
        
        return -1;
    }
    MYOBJECT_API DWORD TransFileAndMem::FoaToRva(IN LPVOID lpvFileBuffer, IN DWORD dwFoa)
    {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpvFileBuffer;//dos头
        PCHDR32  pNtHeader = NULL;//nt头

        //dos头
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
#if _DEBUG
            printf("(RVA转换成FOA阶段)读取的文件不是标准PE文件\r\n");
#endif
            return -1;
        }

        //NT头
        pNtHeader = (PCHDR32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        {
#if _DEBUG
            printf("(RVA转换成FOA阶段)读取的文件不是标准PE文件\r\n");
#endif
            return -1;
        }

        PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeader + pNtHeader->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + sizeof(DWORD));

        for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i, ++pSectionHeader)
        {	//判断 :  Misc.VirtualSize+ VirtualAddress 内存偏移+节数据没对齐的大小>image_panyi>内存偏移 VirtualAddress (即是在文件的哪个节中)
            if ((dwFoa >= pSectionHeader->PointerToRawData) && (dwFoa < pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData))
            {

                return dwFoa - pSectionHeader->PointerToRawData + pSectionHeader->VirtualAddress;
            }
        }

        if (dwFoa <= ((DWORD)pSectionHeader - (DWORD)lpvFileBuffer))
        {
            return dwFoa;
        }

        return -1;
    }


    struct OverlapFile
    {
        HANDLE hFile;
        HANDLE hEvent;
        DWORD dwSize;
        DWORD dwPostionFile;
        LPVOID pbBufferBegin;
    };
    VOID NTAPI TaskHandler(
        _Inout_     PTP_CALLBACK_INSTANCE Instance,
        _Inout_opt_ PVOID                 Context,
        _Inout_     PTP_WORK              Work
    )
    {
        OverlapFile* overlapFile = (OverlapFile*)Context;
        OVERLAPPED olWrite = { 0 };
        olWrite.hEvent = overlapFile->hEvent;
        olWrite.Offset = SetFilePointer(overlapFile->hFile, overlapFile->dwPostionFile, NULL, FILE_BEGIN);
        bool bWirteDone = WriteFile(overlapFile->hFile, overlapFile->pbBufferBegin, overlapFile->dwSize, NULL, &olWrite);
        DWORD dwError = GetLastError();
        if (!bWirteDone && (dwError == ERROR_IO_PENDING))
        {
            WaitForSingleObject(olWrite.hEvent,INFINITE);
            bWirteDone = TRUE;
#if _DEBUG
            printf("线程池异步写入成功");
#endif
            if (!ResetEvent(overlapFile->hEvent))
            {
                printf("ResetEvent filed error=%d",GetLastError());
            }
            overlapFile->pbBufferBegin = (LPVOID)((uint64_t)overlapFile->pbBufferBegin + overlapFile->dwSize);
            overlapFile->dwPostionFile += overlapFile->dwSize;
        }
        else
        {
#if _DEBUG
            printf("线程池异步写入 filed error=%d", GetLastError());
#endif
        }

    }//回调函数格式
    MYOBJECT_API BOOL TransFileAndMem::MemeryTOFile(IN LPVOID pMemBuffer, IN size_t size, IN LPCTSTR lpszFile)
    {

        OverlapFile overlapFile = { 0 };
        overlapFile.pbBufferBegin = pMemBuffer;
        overlapFile.dwSize = 0x200;
        overlapFile.hFile = CreateFile(lpszFile, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED, NULL);

        if (overlapFile.hFile == INVALID_HANDLE_VALUE)
        {
#if _DEBUG
            printf("CreateFile filed error=%d", GetLastError());
#endif
            return FALSE;
        }
        DWORD dwError = GetLastError();


        overlapFile.hEvent = CreateEvent(NULL, TRUE, FALSE, TEXT("WriteFile"));

        if (NULL == overlapFile.hEvent)
        {
#if _DEBUG
            printf("CreateEvent filed error=%d", GetLastError());
#endif
            return FALSE;
        }
        PTP_WORK pWorkItem = CreateThreadpoolWork(TaskHandler, &overlapFile, NULL);

        while (size > overlapFile.dwPostionFile)
        {
            SubmitThreadpoolWork(pWorkItem);
            WaitForThreadpoolWorkCallbacks(pWorkItem, FALSE);
        }
        CloseThreadpoolWork(pWorkItem);
        CloseHandle(overlapFile.hEvent);
        CloseHandle(overlapFile.hFile);
        return TRUE;
    }
    MYOBJECT_API DWORD TransFileAndMem::m_GetFileSize(LPCVOID pImageBuffer) noexcept
    {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pImageBuffer;
        PCHDR32 pNtHeader;
        pNtHeader = (PCHDR32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
        DWORD dwSetionPosition = (DWORD)pDosHeader + pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(_IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader;
        //节表
        PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)dwSetionPosition;
        //找到最后一个节表
        PIMAGE_SECTION_HEADER pLastSetion = (PIMAGE_SECTION_HEADER)(pSectionHeader + pNtHeader->FileHeader.NumberOfSections - 1);

        size_t fileSize = pLastSetion->PointerToRawData + pLastSetion->SizeOfRawData;
        /*最后一个节的位置+长度 为最后的磁盘文件的长度*/
        return fileSize;
    }
    MYOBJECT_API DWORD TransFileAndMem::FixTheImageBase(DWORD dwImageBaseNew, vecReloc& vecReloc)
    {
        if (_lpvOldFilePosition == NULL)
            return -1;
        transformFileToImage();
        if (_bFileIs32)
        {
            PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)_lpvNewMemPosition;
            PIMAGE_NT_HEADERS32 pNtHeader = (PIMAGE_NT_HEADERS32)((DWORD)pDosHeader + pDosHeader->e_lfanew);
            DWORD dwImageFix = dwImageBaseNew - pNtHeader->OptionalHeader.ImageBase;
            pNtHeader->OptionalHeader.ImageBase = dwImageBaseNew;
            
            auto fAddAdress = [pDosHeader](DWORD dwRva)->PDWORD {
                return PDWORD(dwRva + (DWORD)pDosHeader);
            };
            
            for (size_t i = 0; i < vecReloc.e_Size(); ++i)
            {
                auto vec = vecReloc[i];
                for (size_t j = 0; j < vec.size(); ++j)
                {
                    auto pair = vec[j];
                    if (pair.first == 3)
                    {
                        *fAddAdress(pair.second) += dwImageFix;
                    }
                }
            }
        }
        else
        {
            
        }
        transformImageToFile();
        writeBackNewFile(TEXT("FixTheImageBase.exe"));
        return EXIT_SUCCESS;
    }

}


}
