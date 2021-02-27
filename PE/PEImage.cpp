#include "../PE/PEImage.h"
#include "../Include/Macro.h"
#include "../Misc/Utils.h"
//#include "../Misc/DynImport.h"

#include <algorithm>

#define TLS32(ptr) ((const IMAGE_TLS_DIRECTORY32*)ptr)  // TLS directory
#define TLS64(ptr) ((const IMAGE_TLS_DIRECTORY64*)ptr)  // TLS directory
#define THK32(ptr) ((const IMAGE_THUNK_DATA32*)ptr)     // Import thunk data
#define THK64(ptr) ((const IMAGE_THUNK_DATA64*)ptr)     // Import thunk data

namespace MyObject
{

namespace pe
{

PEImage::PEImage( void )
{
}

PEImage::~PEImage( void )
{
    Release();
}

/// <summary>
/// Load image from file
/// </summary>
/// <param name="path">File path</param>
/// <param name="skipActx">If true - do not initialize activation context</param>
/// <returns>Status code</returns>
NTSTATUS PEImage::Load( const std::wstring& path, bool skipActx /*= false*/ )
{
    Release( true );
    _imagePath = path;
    _noFile = false;

    _hFile = CreateFileW(
        path.c_str(), FILE_GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL
        );
    _fileSize=  GetFileSize(_hFile, NULL);

    if (_hFile)
    {
        // Try mapping as image
        _hMapping = CreateFileMappingW( _hFile, NULL, SEC_IMAGE | PAGE_READONLY , 0, 0, NULL );
        if (_hMapping)
        {
            _isPlainData = false;
            _pFileBase = Mapping( MapViewOfFile( _hMapping, FILE_MAP_READ, 0, 0, 0 ) );
        }
        // Map as simple datafile
        else
        {
            _isPlainData = true;
            _hMapping = CreateFileMappingW( _hFile, NULL, PAGE_READONLY, 0, 0, NULL );

            if (_hMapping)
                _pFileBase = Mapping( MapViewOfFile( _hMapping, FILE_MAP_READ, 0, 0, 0 ) );
        }

        // Mapping failed
        if (!_pFileBase)
            return LastNtStatus();
    }
    else
        return LastNtStatus();

    auto status = Parse();
    if (!NT_SUCCESS( status ))
        return status;

    return skipActx ? status : PrepareACTX( _imagePath.c_str() );
}
NTSTATUS PEImage::Load_Write(const std::wstring& path)
{
    Release(true);
    _imagePath = path;
    _noFile = false;

    _hFile = CreateFileW(
        path.c_str(), FILE_GENERIC_READ|FILE_GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL, OPEN_EXISTING, 0, NULL
    );
    _fileSize = GetFileSize(_hFile, NULL);

    if (_hFile)
    {
        // Try mapping as image
        _hMapping = CreateFileMappingW(_hFile, NULL, SEC_IMAGE | PAGE_EXECUTE_READWRITE, 0, 0, NULL);
        if (_hMapping)
        {
            _isPlainData = false;
            _pFileBase = Mapping(MapViewOfFile(_hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0));
        }
        // Map as simple datafile
        else
        {
            _isPlainData = true;
            _hMapping = CreateFileMappingW(_hFile, NULL, PAGE_READWRITE, 0, 0, NULL);

            if (_hMapping)
                _pFileBase = Mapping(MapViewOfFile(_hMapping, FILE_MAP_READ|FILE_MAP_WRITE, 0, 0, 0));
        }

        // Mapping failed
        if (!_pFileBase)
            return LastNtStatus();
    }
    else
        return LastNtStatus();

    auto status = Parse();
    if (!NT_SUCCESS(status))
        return status;

    return status;
}
/// <summary>
/// 从内存位置加载映像
/// </summary>
/// <param name="pData">Image data</param>
/// <param name="size">Data size.</param>
/// <param name="plainData">If false - data has image layout</param>
/// <returns>Status code</returns>
NTSTATUS PEImage::Load( void* pData, size_t size, bool plainData /*= true */ )
{
    Release( true );

    _noFile = true;
    _pFileBase = pData;
    _isPlainData = plainData;

    auto status = Parse();
    if (!NT_SUCCESS( status ))
        return status;

    return PrepareACTX();
}

/// <summary>
/// Reload closed image
/// </summary>
/// <returns>Status code</returns>
NTSTATUS PEImage::Reload()
{
    if (_isPlainData)
        return Load_Write(_imagePath);
    else
        return Load( _imagePath );
}

/// <summary>
/// 释放内存映射文件
/// </summary>
/// <param name="temporary">为文件重写打开保留文件路径</param>
void PEImage::Release( bool temporary /*= false*/ )
{
    _pFileBase.reset();
    _hMapping.reset();
    _hFile.reset();
    _hctx.reset();

    // Reset pointers to data
    _pImageHdr32 = nullptr;
    _pImageHdr64 = nullptr;

    if(!temporary)
    {
        _imagePath.clear();

        // Ensure temporary file is deleted
        if (_noFile)
            DeleteFileW( _manifestPath.c_str() );

        _manifestPath.clear();
    }
}

/// <summary>
/// 分析pe文件
/// </summary>
/// <returns>状态码</returns>
NTSTATUS PEImage::Parse( void* pImageBase /*= nullptr*/ ) //pe分析
{
    const IMAGE_DOS_HEADER *pDosHdr = nullptr;
    const IMAGE_SECTION_HEADER *pSection = nullptr;

    if (pImageBase != nullptr)
        _pFileBase = pImageBase;//为内存映像文件地址赋值

    // 如果_pFileBase = NULL 说明发生了错误
    if (!_pFileBase)
        return STATUS_INVALID_ADDRESS;

    // 获取 DOS header
    pDosHdr = reinterpret_cast<const IMAGE_DOS_HEADER*>(_pFileBase.get());

    // 是否是PE文件
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return STATUS_INVALID_IMAGE_FORMAT;
    p_e_magic = (int16_t*)&pDosHdr->e_magic;
    
    // 获取PE header
    p_e_lfanew = (uint32_t*)&pDosHdr->e_lfanew;

    _pImageHdr32 = reinterpret_cast<PCHDR32>(reinterpret_cast<const uint8_t*>(pDosHdr) + pDosHdr->e_lfanew);
    _pImageHdr64 = reinterpret_cast<PCHDR64>(_pImageHdr32);

    // 文件不是一个有效的PE文件
    if (_pImageHdr32->Signature != IMAGE_NT_SIGNATURE)
        return STATUS_INVALID_IMAGE_FORMAT;

    auto GetHeaderData = [this, &pSection]( auto pImageHeader )
    {
        p_Machine = (uint16_t*)&pImageHeader->FileHeader;
        p_NumberOfSections = (uint16_t*)((uint64_t)&pImageHeader->FileHeader+2);
        p_TimeDateStamp = (uint32_t*)((uint64_t)&pImageHeader->FileHeader+4);
        p_SizeOfOptionalHeader = (uint16_t*)((uint64_t)&pImageHeader->FileHeader + 8);
        p_FillCharacteristics = (uint16_t*)((uint64_t)&pImageHeader->FileHeader + 10);

        p_Magic = (uint16_t*)((uint64_t)&pImageHeader->OptionalHeader);
        p_MajorLinkerVersion = (uint8_t*)((uint64_t)&pImageHeader->OptionalHeader + 2);
        p_MinorLinkerVersion = (uint8_t*)((uint64_t)&pImageHeader->OptionalHeader + 3);
        p_SizeOfCode = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 4);
        p_SizeOfInitializedData = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 8);
        p_SizeOfUninitializedData = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 12);
        p_AddressOfEntryPoint = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 16);
        p_BaseOfCode = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 20);

        p_SectionAlignment = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 32);
        p_FileAlignment = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 36);
        p_MajorOperatingSystemVersion = (uint16_t*)((uint64_t)&pImageHeader->OptionalHeader + 40);
        p_MinorOperatingSystemVersion = (uint16_t*)((uint64_t)&pImageHeader->OptionalHeader + 42);
        p_MajorImageVersion = (uint16_t*)((uint64_t)&pImageHeader->OptionalHeader + 44);
        p_MinorImageVersion = (uint16_t*)((uint64_t)&pImageHeader->OptionalHeader + 46);
        p_MajorSubsystemVersion = (uint16_t*)((uint64_t)&pImageHeader->OptionalHeader + 48);
        p_MinorSubsystemVersion = (uint16_t*)((uint64_t)&pImageHeader->OptionalHeader + 50);
        p_Win32VersionValue = (uint16_t*)((uint64_t)&pImageHeader->OptionalHeader + 52);
        p_SizeOfImage = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 56);//可能有问题
        p_SizeOfHeaders = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 60);
        p_CheckSum = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 64);
        p_Subsystem = (uint16_t*)((uint64_t)&pImageHeader->OptionalHeader + 68);
        p_DllCharacteristics = (uint16_t*)((uint64_t)&pImageHeader->OptionalHeader + 70);

        if (!this->_is64)
        {
            p_BaseOfData_32 = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 24);
            p_ImageBase_32 = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 28);

            p_SizeOfStackReserve_32 = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 72);
            p_SizeOfStackCommit_32 = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 76);
            p_SizeOfHeapReserve_32 = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 80);
            p_SizeOfHeapCommit_32 = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 84);
            p_LoaderFlags = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 88);
            p_NumberOfRvaAndSizes = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 92);
        }
        else
        {
            p_ImageBase_64 = (uint64_t*)((uint64_t)&pImageHeader->OptionalHeader + 24);
            p_SizeOfStackReserve_64 = (uint64_t*)((uint64_t)&pImageHeader->OptionalHeader + 72);
            p_SizeOfStackCommit_64 = (uint64_t*)((uint64_t)&pImageHeader->OptionalHeader + 80);
            p_SizeOfHeapReserve_64 = (uint64_t*)((uint64_t)&pImageHeader->OptionalHeader + 88);
            p_SizeOfHeapCommit_64 = (uint64_t*)((uint64_t)&pImageHeader->OptionalHeader + 96);
            p_LoaderFlags = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 104);
            p_NumberOfRvaAndSizes = (uint32_t*)((uint64_t)&pImageHeader->OptionalHeader + 108);
        }

        _imgBase = pImageHeader->OptionalHeader.ImageBase;
        _imgSize = pImageHeader->OptionalHeader.SizeOfImage;
        _hdrSize = pImageHeader->OptionalHeader.SizeOfHeaders;
        _epRVA = pImageHeader->OptionalHeader.AddressOfEntryPoint;
        _subsystem = pImageHeader->OptionalHeader.Subsystem;
        _DllCharacteristics = pImageHeader->OptionalHeader.DllCharacteristics;

        pSection = reinterpret_cast<const IMAGE_SECTION_HEADER*>(pImageHeader + 1);
    };

    // 检查是否时x64的映像
    if (_pImageHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        _is64 = true;
        GetHeaderData( _pImageHdr64 );
    }
    else
    {
        _is64 = false;
        GetHeaderData( _pImageHdr32 );
    }

    // 检查是否时Exe文件
    _isExe = !(_pImageHdr32->FileHeader.Characteristics & IMAGE_FILE_DLL);

    // 检查是否时COM文件 .net程序
    auto pCorHdr = reinterpret_cast<PIMAGE_COR20_HEADER>(DirectoryAddress( IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR ));

    _isPureIL = (pCorHdr && (pCorHdr->Flags & COMIMAGE_FLAGS_ILONLY)) ? true : false;

    if (_isPureIL)
    {
        _ILFlagOffset = static_cast<int32_t>(
            reinterpret_cast<uint8_t*>(pCorHdr)
            - reinterpret_cast<uint8_t*>(_pFileBase.get())
            + static_cast<int32_t>(offsetof( IMAGE_COR20_HEADER, Flags )));
    }

    // 获取节
    for (int i = 0; i < _pImageHdr32->FileHeader.NumberOfSections; ++i, ++pSection)
    {
        _sections.emplace_back(*pSection);

        _pSections.emplace_back(const_cast<PIMAGE_SECTION_HEADER>(pSection));
    }

    return STATUS_SUCCESS;
}
#if !ISNEIHE
void PEImage::ShowDirectory()
{
    const char* aszName[] =
    {
        "导出表",
        "导入表",
        "资源表",
        "异常结构表",
        "安全证书表",
        "重定位表",
        "调试信息表",
        "版权信息表",
        "全局指针表",
        "TLS表",
        "加载配置表",
        "绑定导入表",
        "IAT表",
        "延迟导入表",
        "COM表结构",
        "保留结构"
    };  
    const IMAGE_DATA_DIRECTORY* idd = _is64 ? _pImageHdr64->OptionalHeader.DataDirectory : _pImageHdr32->OptionalHeader.DataDirectory;
    for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i)
    {
        printf("%s%s----------\n", aszName[i], &"----------"[strlen(aszName[i])]);
        printf("VirtualAddress = <%x> \nSize(无用) = <%x>\n\n", idd->VirtualAddress, idd->Size);
        ++idd;
    }
}
#endif
/// <summary>
/// Processes image imports
/// </summary>
/// <param name="useDelayed">Process delayed import instead</param>
/// <returns>Import data</returns>
mapImports& PEImage::GetImports(bool useDelayed /*= false*/)
{
    if (useDelayed)
    {
        auto pImportTbl = reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(DirectoryAddress(IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT));
        if (!pImportTbl)
            return _delayImports;

        // Delayed Imports
        for (; pImportTbl->DllNameRVA; ++pImportTbl)
        {
            uint8_t* pRVA = nullptr;
            DWORD IAT_Index = 0;
            char* pDllName = reinterpret_cast<char*>(ResolveRVAToVA(pImportTbl->DllNameRVA));
            auto dllStr = Utils::AnsiToWstring(pDllName);

            pRVA = reinterpret_cast<uint8_t*>(ResolveRVAToVA(pImportTbl->ImportNameTableRVA));

            while (_is64 ? THK64(pRVA)->u1.AddressOfData : THK32(pRVA)->u1.AddressOfData)
            {
                uint64_t AddressOfData = _is64 ? THK64(pRVA)->u1.AddressOfData : THK32(pRVA)->u1.AddressOfData;
                auto pAddressTable = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(ResolveRVAToVA(static_cast<uintptr_t>(AddressOfData)));
                ImportData data;

                // import by name
                if (AddressOfData < (_is64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32) && pAddressTable->Name[0])
                {
                    data.importByOrd = false;
                    data.importName = reinterpret_cast<const char*>(pAddressTable->Name);
                    data.importOrdinal = 0;
                }
                // import by ordinal
                else
                {
                    data.importByOrd = true;
                    data.importOrdinal = static_cast<WORD>(AddressOfData & 0xFFFF);
                }

                data.ptrRVA = pImportTbl->ImportAddressTableRVA + IAT_Index;

                _delayImports[dllStr].emplace_back(data);

                // Go to next entry
                pRVA += _is64 ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);
                IAT_Index += _is64 ? sizeof(uint64_t) : sizeof(uint32_t);
            }
        }

        return _delayImports;
    }
    else
    {

        auto pImportTbl = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(DirectoryAddress(IMAGE_DIRECTORY_ENTRY_IMPORT,VA));
        if (!pImportTbl || pImportTbl == _pFileBase.get())
            return _imports;
        // Imports 
        for (; pImportTbl->Name; ++pImportTbl)//遍历导入表数组 结束是遇到0
        {
            uint32_t pRVAInt = 0;
            uint32_t pRVAIat = 0;
            char *pDllName = reinterpret_cast<char*>(ResolveRVAToVA( pImportTbl->Name,VA));//获取DLL的名字
            auto dllStr = Utils::AnsiToWstring( pDllName );//转为Unicode字符

            pRVAInt = static_cast<uint32_t>(ResolveRVAToVA(pImportTbl->OriginalFirstThunk, VA));//int表
            pRVAIat = static_cast<uint32_t>(pImportTbl->FirstThunk);//iat表

            while (_is64 ? THK64(pRVAInt)->u1.AddressOfData : THK32(pRVAInt)->u1.AddressOfData)
            {
                uint64_t AddressOfData = _is64 ? THK64(pRVAInt)->u1.AddressOfData : THK32(pRVAInt)->u1.AddressOfData;//64 或者 32位数据
                
                
                /*typedef struct _IMAGE_IMPORT_BY_NAME {
                    WORD    Hint; //是不准确的
                    CHAR   Name[1];
                } IMAGE_IMPORT_BY_NAME, * PIMAGE_IMPORT_BY_NAME;*/
                auto pAddressTable = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(ResolveRVAToVA( static_cast<uintptr_t>(AddressOfData),VA ));
                ImportData data;

                if (AddressOfData < (_is64 ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32) && pAddressTable->Name[0])//判断是否按照序号导出
                {
                    //按照名字导出
                    data.importByOrd   = false;
                    data.importName    = reinterpret_cast<const char*>(pAddressTable->Name);
                    data.importOrdinal = 0;
                }
                // 按照序号导出
                else
                {
                    data.importByOrd   = true;
                    data.importOrdinal = static_cast<WORD>(AddressOfData & 0xFFFF);
                }

                // 保存对应的IAT的RVA 
                data.ptrRVA = static_cast<uintptr_t>(pRVAIat);


                _imports[dllStr].emplace_back( data );//加入到数据结构中

                // Go to next entry
                pRVAIat += _is64 ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);
                pRVAInt += _is64 ? sizeof(IMAGE_THUNK_DATA64) : sizeof(IMAGE_THUNK_DATA32);
            }
        }

        return _imports;


    }
}

/// <summary>
/// 获取导入绑定表
/// </summary>
/// <returns>返回绑定导入表</returns>
mapBoundImports& PEImage::GetBoundPort()
{
    uintptr_t dwRvaName = DirectoryAddress(IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, RVA); //在头中 RVA和FOA一致
    dwRvaName += (uintptr_t)_pFileBase.get();
    auto  pBoundImportTbl = reinterpret_cast<PIMAGE_BOUND_IMPORT_DESCRIPTOR>(dwRvaName);
    if (!pBoundImportTbl || pBoundImportTbl == _pFileBase.get())
        return _boundimport;
    // 绑定导入表
    for (; pBoundImportTbl->TimeDateStamp; )//遍历导入表数组 结束是遇到0
    {
        const char *pDllName = reinterpret_cast<const char*>(dwRvaName+ pBoundImportTbl->OffsetModuleName);//不用进行转换了
        auto wszName = Utils::AnsiToWstring(pDllName);

        BoundImportData bidTemp(pBoundImportTbl->TimeDateStamp, pBoundImportTbl->NumberOfModuleForwarderRefs);
        PIMAGE_BOUND_FORWARDER_REF pBoundRef = reinterpret_cast<PIMAGE_BOUND_FORWARDER_REF>(pBoundImportTbl+1);
        for (size_t i = 0; i < pBoundImportTbl->NumberOfModuleForwarderRefs; ++i)
        {
            bidTemp.vecRef[i].uTimeDateStamp = pBoundRef->TimeDateStamp;
            bidTemp.vecRef[i].strDllName = reinterpret_cast<const char*>(dwRvaName + pBoundRef->OffsetModuleName);//不用进行转换了
            pBoundRef++;
        }
        _boundimport.emplace(wszName, bidTemp);
        pBoundImportTbl = reinterpret_cast<PIMAGE_BOUND_IMPORT_DESCRIPTOR>(pBoundRef);
    }

    return _boundimport;
}

void PEImage::ShowImports(mapImports& imports)
{
    for (auto vec : imports)
    {
        printf("导入DLL名字为：<%-.20S>\r\n", vec.first.c_str());
        for (auto data : vec.second)
        {
            if (data.importByOrd)
            {
                printf("----以序号导入，对应IAT地址为<%#-.8x>,导入序号为:<%#.4x>\r\n", data.ptrRVA,data.importOrdinal);
            }
            else
            {
                printf("----以名字导入，对应IAT地址为<%#-.8x>,导入名称为:<%-.40s>\r\n", data.ptrRVA,data.importName.c_str());
            }
        }
        printf("\n\n\n");
    }
}
void PEImage::ShowBoundImport(mapBoundImports& boundimports)
{
    for (auto vec : boundimports)
    {
        printf("绑定导入的DLL名字为：<%-.20S>\r\n", vec.first.c_str());
        for (auto data : vec.second.vecRef)
        {
            printf("----绑定导入的DLL REF 名字为：<%-.20s>\r\n", data.strDllName.c_str());
        }
        printf("\n\n");
    }
}

/// <summary>
/// Retrieve all exported functions with names
/// </summary>
/// <param name="names">Found exports</param>
void PEImage::GetExports( vecExports& exports )
{
    exports.clear();
    Reload();


    auto pExport = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(DirectoryAddress( IMAGE_DIRECTORY_ENTRY_EXPORT ,VA));
    if (pExport == _pFileBase.get()|| pExport == NULL)
        return;

    exports.strName = reinterpret_cast<const char*>(ResolveRVAToVA(pExport->Name));
    exports.uBase = pExport->Base;
    exports.uFoa = DirectoryAddress(IMAGE_DIRECTORY_ENTRY_EXPORT, FOA);
    exports.uRva = DirectoryAddress(IMAGE_DIRECTORY_ENTRY_EXPORT, RVA);

    const auto idd = _is64 ? _pImageHdr64->OptionalHeader.DataDirectory : _pImageHdr32->OptionalHeader.DataDirectory;
    exports.uFoaDerictory = uint32_t(idd) - uint32_t(_pFileBase.get());


    DWORD *pAddressOfNames  = NULL;
    DWORD *pAddressOfFuncs  = NULL;
    WORD  *pAddressOfOrds   = NULL;

    pAddressOfNames = reinterpret_cast<DWORD*>(ResolveRVAToVA(pExport->AddressOfNames,FOA) + reinterpret_cast<uintptr_t>(_pFileBase.get()));
    pAddressOfFuncs = reinterpret_cast<DWORD*>(ResolveRVAToVA(pExport->AddressOfFunctions,FOA) + reinterpret_cast<uintptr_t>(_pFileBase.get()));
    pAddressOfOrds  = reinterpret_cast<WORD*> (ResolveRVAToVA(pExport->AddressOfNameOrdinals,FOA) + reinterpret_cast<size_t>(_pFileBase.get()));
    //需要的话 需要做FOA到VA的转换



    for (DWORD i = 0; i < pExport->NumberOfNames; ++i)
    {
        exports.vecstrNames.emplace_back(reinterpret_cast<const char*>(ResolveRVAToVA(*pAddressOfNames++)));
        exports.vecwOrds.emplace_back(*pAddressOfOrds++);
    }

    for (DWORD i = 0; i < pExport->NumberOfFunctions; ++i)
    {
        exports.vecdwRvaOfFuncs.emplace_back(*pAddressOfFuncs);
        exports.vecdwFOAOfFuncs.emplace_back(ResolveRVAToVA(*pAddressOfFuncs++, FOA));
    }

    return Release( true );
}
/// <summary>
/// 获取重定位表
/// </summary>
/// <param name="reloc">重定位表的存储空间</param>
void PEImage::GetReloc(vecReloc& reloc)
{
    reloc.e_clear();
    Reload();
    auto pReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(DirectoryAddress(IMAGE_DIRECTORY_ENTRY_BASERELOC, VA));
    if (pReloc == _pFileBase.get()|| pReloc == NULL)
        return;
    //获取重定位表的FOA->VA(因为可能不是内存映像)
    reloc.uFoaOFReloc = DirectoryAddress(IMAGE_DIRECTORY_ENTRY_BASERELOC, FOA);

    while (1)//按块进行处理
    {
        RelocData rdTemp((pReloc->SizeOfBlock - 8) / 2);//(pReloc->SizeOfBlock - 8) / 2 表示该页有多少需要重定位
        rdTemp.PageRVA = pReloc->VirtualAddress;
        rdTemp.BlockSize = pReloc->SizeOfBlock;
        //初始化
        PWORD pwTemp = reinterpret_cast<PWORD>((DWORD)pReloc + 8);
        //从item开始 向rdTemp添加数据
        pReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>((DWORD)pReloc + pReloc->SizeOfBlock);
        //指向下一个重定位表块
        for ( ; pwTemp!=(PWORD)pReloc;pwTemp++)
        {
            rdTemp.e_push_back(*pwTemp);
        }
        reloc.e_push_back(rdTemp);//塞入我们的结构体中
        if (pReloc->VirtualAddress == 0 && pReloc->SizeOfBlock == 0)//说明是最后一个块 退出循环
            break;
    }
    return Release(true);
}

/// <summary>
/// Retrieve data directory address
/// </summary>
/// <param name="index">Directory index</param>
/// <param name="keepRelative">Keep address relative to image base</param>
/// <returns>Directory address</returns>
uintptr_t PEImage::DirectoryAddress( int index, AddressType type /*= VA*/ ) const
{
    // Sanity check
    if (index < 0 || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        return 0;

    const auto idd = _is64 ? _pImageHdr64->OptionalHeader.DataDirectory  : _pImageHdr32->OptionalHeader.DataDirectory;
    return idd[index].VirtualAddress == 0 ? 0 : ResolveRVAToVA( idd[index].VirtualAddress, type );
}

/// <summary>
/// Get data directory size
/// </summary>
/// <param name="index">Data directory index</param>
/// <returns>Data directory size</returns>
size_t PEImage::DirectorySize( int index ) const
{
    // Sanity check
    if (index < 0 || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        return 0;

    const IMAGE_DATA_DIRECTORY* idd = _is64 ? _pImageHdr64->OptionalHeader.DataDirectory : _pImageHdr32->OptionalHeader.DataDirectory;
    return idd[index].VirtualAddress != 0 ? static_cast<size_t>(idd[index].Size) : 0;
}


/// <summary>
/// Resolve virtual memory address to physical file offset
/// </summary>
/// <param name="Rva">Memory address</param>
/// <param name="keepRelative">Keep address relative to file start</param>
/// <returns>Resolved address</returns>
uintptr_t PEImage::ResolveRVAToVA( uintptr_t Rva, AddressType type /*= VA*/ ) const
{
    switch (type)
    {
    case MyObject::pe::RVA:
        return Rva;

    case MyObject::pe::VA:
    case MyObject::pe::FOA:
        if (_isPlainData)
        {
            for (auto& sec : _sections)
            {
                if (Rva >= sec.VirtualAddress && Rva < sec.VirtualAddress + sec.Misc.VirtualSize)
                    if (type == VA)
                        return reinterpret_cast<uintptr_t>(_pFileBase.get()) + Rva - sec.VirtualAddress + sec.PointerToRawData;
                    else
                        return Rva - sec.VirtualAddress + sec.PointerToRawData;
            }

            return 0;
        }
        else
            return (type == VA) ? (reinterpret_cast<uintptr_t>(_pFileBase.get()) + Rva) : Rva;

    default:
        return 0;
    }

}

/// <summary>
/// Retrieve image TLS callbacks
/// Callbacks are rebased for target image
/// </summary>
/// <param name="targetBase">Target image base</param>
/// <param name="result">Found callbacks</param>
/// <returns>Number of TLS callbacks in image</returns>
int PEImage::GetTLSCallbacks( module_t targetBase, std::vector<ptr_t>& result ) const
{
    uint8_t *pTls = reinterpret_cast<uint8_t*>(DirectoryAddress( IMAGE_DIRECTORY_ENTRY_TLS ));
    uint64_t* pCallback = 0;
    if (!pTls)
        return 0;

    uint64_t offset = _is64 ? TLS64( pTls )->AddressOfCallBacks : TLS32( pTls )->AddressOfCallBacks;
    if (offset == 0)
        return 0;

    // Not at base
    if (imageBase() != reinterpret_cast<module_t>(_pFileBase.get()))
        pCallback = reinterpret_cast<uint64_t*>(ResolveRVAToVA( static_cast<size_t>(offset - imageBase()) ));
    else
        pCallback = reinterpret_cast<uint64_t*>(offset);

    if(_is64)
    {
        for (; *pCallback; pCallback++)
            result.push_back( REBASE( *pCallback, imageBase(), targetBase ) );
    }
    else
    {
        for (uint32_t *pCallback2 = reinterpret_cast<uint32_t*>(pCallback); *pCallback2; pCallback2++)
            result.push_back( REBASE( *pCallback2, imageBase(), targetBase ) );
    }

    return (int)result.size();
}

/// <summary>
/// Prepare activation context
/// </summary>
/// <param name="filepath">Path to PE file. If nullptr - manifest is extracted from memory to disk</param>
/// <returns>Status code</returns>
NTSTATUS PEImage::PrepareACTX( const wchar_t* filepath /*= nullptr*/ )
{
    wchar_t tempPath[256] = { 0 };
    uint32_t manifestSize = 0;

    ACTCTXW act = { 0 };
    act.cbSize = sizeof( act );

    // No manifest found, skip
    auto pManifest = GetManifest( manifestSize, _manifestIdx );
    if (!pManifest)
        return STATUS_SUCCESS;

    //
    // Dump manifest to TMP folder
    //
    if (filepath == nullptr)
    {
        wchar_t tempDir[256] = { 0 };

        GetTempPathW( ARRAYSIZE( tempDir ), tempDir );
        if (GetTempFileNameW( tempDir, L"ImageManifest", 0, tempPath ) == 0)
            return STATUS_SXS_CANT_GEN_ACTCTX;
     
        auto hTmpFile = Handle( CreateFileW( tempPath, FILE_GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL ) );
        if (hTmpFile)
        {
            DWORD bytes = 0;
            WriteFile( hTmpFile, pManifest, manifestSize, &bytes, NULL );
            hTmpFile.reset();

            act.lpSource = tempPath;
            _manifestPath = tempPath;
        }
        else
            return LastNtStatus();
    }
    else
    {
        act.dwFlags = ACTCTX_FLAG_RESOURCE_NAME_VALID;
        act.lpResourceName = MAKEINTRESOURCEW( _manifestIdx );
        act.lpSource = filepath;

        _manifestPath = _imagePath;
    }  
   
    // Create ACTX
    _hctx = CreateActCtxW( &act );
    if (_hctx)
        return STATUS_SUCCESS;

    // Return success if current process is protected
    if (LastNtStatus() == STATUS_ACCESS_DENIED)
    {
        _manifestIdx = 0;
        return STATUS_SUCCESS;
    }

    return LastNtStatus();
}

/// <summary>
/// Get manifest from image data
/// </summary>
/// <param name="size">Manifest size</param>
/// <param name="manifestID">Mmanifest ID</param>
/// <returns>Manifest data</returns>
void* PEImage::GetManifest( uint32_t& size, int32_t& manifestID )
{
    // 3 levels of pointers to nodes
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *pDirNode1 = nullptr;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *pDirNode2 = nullptr;
    const IMAGE_RESOURCE_DIRECTORY_ENTRY *pDirNode3 = nullptr;

    // 3 levels of nodes
    const IMAGE_RESOURCE_DIRECTORY       *pDirNodePtr1 = nullptr;
    const IMAGE_RESOURCE_DIRECTORY       *pDirNodePtr2 = nullptr;

    // resource entry data
    const IMAGE_RESOURCE_DATA_ENTRY      *pDataNode = nullptr;

    size_t ofst_1 = 0;  // first level nodes offset
    size_t ofst_2 = 0;  // second level nodes offset
    size_t ofst_3 = 0;  // third level nodes offset

    // Get section base
    auto secBase = DirectoryAddress( IMAGE_DIRECTORY_ENTRY_RESOURCE );
    if (secBase == 0)
    {
        size = 0;
        manifestID = 0;
        return nullptr;
    }

    pDirNodePtr1 = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(secBase);
    ofst_1 += sizeof( IMAGE_RESOURCE_DIRECTORY );

    // first-level nodes
    for (int i = 0; i < pDirNodePtr1->NumberOfIdEntries + pDirNodePtr1->NumberOfNamedEntries; ++i)
    {
        pDirNode1 = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(secBase + ofst_1);

        // Not a manifest directory
        if (!pDirNode1->DataIsDirectory || pDirNode1->Id != 0x18)
        {
            ofst_1 += sizeof( IMAGE_RESOURCE_DIRECTORY_ENTRY );
            continue;
        }

        pDirNodePtr2 = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(secBase + pDirNode1->OffsetToDirectory);
        ofst_2 = pDirNode1->OffsetToDirectory + sizeof( IMAGE_RESOURCE_DIRECTORY );

        // second-level nodes
        for (int j = 0; j < pDirNodePtr2->NumberOfIdEntries + pDirNodePtr2->NumberOfNamedEntries; ++j)
        {
            pDirNode2 = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(secBase + ofst_2);

            if (!pDirNode2->DataIsDirectory)
            {
                ofst_2 += sizeof( IMAGE_RESOURCE_DIRECTORY_ENTRY );
                continue;
            }

            // Check if this is a valid manifest resource
            if (pDirNode2->Id == 1 || pDirNode2->Id == 2 || pDirNode2->Id == 3)
            {
                ofst_3 = pDirNode2->OffsetToDirectory + sizeof( IMAGE_RESOURCE_DIRECTORY );
                pDirNode3 = reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(secBase + ofst_3);
                pDataNode = reinterpret_cast<const IMAGE_RESOURCE_DATA_ENTRY*>(secBase + pDirNode3->OffsetToData);

                manifestID = pDirNode2->Id;
                size = pDataNode->Size;

                return reinterpret_cast<void*>(ResolveRVAToVA( pDataNode->OffsetToData ));
            }

            ofst_2 += sizeof( IMAGE_RESOURCE_DIRECTORY_ENTRY );
        }

        ofst_1 += sizeof( IMAGE_RESOURCE_DIRECTORY_ENTRY );
    }

    return nullptr;
}

}

}
