#pragma once

#include "../Config.h"
#include "../Include/Winheaders.h"
#include "../Include/Type.h"
#include "../Include/HandleGuard.h"
#include "../Misc/Utils.h"

#include <string>
#include <memory>
#include <vector>
#include <map>
#include <unordered_map>
#include <set>
#include <list>

namespace MyObject
{

namespace pe
{

enum AddressType
{
    RVA,    // 相对虚拟地址偏移
    VA,     // 真实地址偏移（不一定是虚拟地址 也有可能是文件地址）
    FOA,    // 相对文件地址偏移
};

/// <summary>
/// 重定位表的信息
/// </summary>
struct RelocData
{
    RelocData(uint32_t uSize) :m_vecu16Item(std::vector<uint16_t>(uSize)) {};

    void e_push_back(uint16_t uItem) {
        m_vecu16Item[m_iPositon++] = uItem;
    }
    std::pair<uint8_t, uint32_t> operator[](typename std::vector<uint16_t>::size_type i){
        auto value = m_vecu16Item[i];
        return { (value&0xf000)>>12,(value&0x0fff) + PageRVA };
    }
    uint32_t size() {
       return  m_vecu16Item.size();
    }
    uint32_t PageRVA = 0;
    uint32_t BlockSize = 0;
private:
    std::vector<uint16_t> m_vecu16Item;
    typename std::vector<uint16_t>::size_type m_iPositon = 0;
};
struct vecReloc
{
    uint32_t uFoaOFReloc = 0;
    void e_clear(void) { vecRelocData.clear(); };
    void e_push_back(RelocData& r) {
        vecRelocData.emplace_back(std::move(r));
    }
    size_t e_Size(void)
    {
        return vecRelocData.size();
    }
    const RelocData& operator[](typename std::vector<RelocData>::size_type i)
    {
        return const_cast<const RelocData&>(vecRelocData[i]);
    }
    void e_ShowReloc(void)
    {
        for (size_t i = 0; i < vecRelocData.size(); ++i)
        {
            printf("重定位块:<%8x>,需要重定位:<%8x>********\r\n", vecRelocData[i].PageRVA, vecRelocData[i].size()-1);
            for (size_t j = 0; j < vecRelocData[i].size()-1; ++j)
            {
                auto ij = vecRelocData[i][j];
                printf("属性:<%x>,RVA:<%x>\r\n", ij.first, ij.second);
            }
        }
    }
private:
    std::vector<RelocData> vecRelocData;
};

/// <summary>
/// 导入表的信息
/// </summary>
struct ImportData
{
    std::string importName;     // Function name
    uintptr_t ptrRVA;            // Function pointer RVA in
    WORD importOrdinal;         // Function ordinal
    bool importByOrd;           // Function is imported by ordinal
};

/// <summary>
/// 绑定导入表的信息
/// </summary>
struct BoundImportData
{
    struct BoundForwaredRefData
    {
        uint32_t uTimeDateStamp; //该DLL需要导入的dll的时间戳
        std::string strDllName;//该DLL需要导入的dll的名字
        BoundForwaredRefData() :uTimeDateStamp(0), strDllName() {}
        BoundForwaredRefData(uint32_t u, std::string str):uTimeDateStamp(u), strDllName(str){}
    };

    uint32_t uTimeDateStamp; //真实的时间戳
    std::vector<BoundForwaredRefData> vecRef; //该DLL需要导入的其他DLL
    BoundImportData(uint32_t u1,uint16_t u2):uTimeDateStamp(u1), vecRef(std::vector<BoundForwaredRefData>(u2)){}
};

/// <summary>
/// 导出表的数据
/// </summary>
struct ExportData
{
    std::string strName;//导出表名字
    uint32_t uBase;//序号导出起始序号
    uint32_t uFoa;//导出表Foa
    uint32_t uRva;//导出表RVA
    uint32_t uFoaDerictory;//目录表的FOA


    std::vector<std::string> vecstrNames;//导出函数的名字
    std::vector<uint16_t>   vecwOrds;//以名字导出的导出函数的序号
    std::vector<uint32_t> vecdwRvaOfFuncs;//导出函数的RVA
    std::vector<uint32_t> vecdwFOAOfFuncs;//导出函数的FOA
    /// <summary>
    /// 设置相关属性
    /// </summary>
    /// <param name="pied"></param>
    /// <summary>
    /// 清空数据
    /// </summary>
    void clear()
    {
        uBase = 0;
        strName.clear();
        vecstrNames.clear();
        vecwOrds.clear();
        vecdwRvaOfFuncs.clear();
        vecdwFOAOfFuncs.clear();
    }
    void e_ShowExportData()
    {
        printf("导出表名字为:%s\r\n", strName.c_str());
        printf("序号--------RVA------FOA------函数名\r\n");
        for (size_t i = 0; i < vecdwFOAOfFuncs.size(); ++i)
        {
            size_t nTemp = m_FindFuncName(i);
            if (vecdwRvaOfFuncs[i] != 0)
                printf("%-4hd        %-6x   %-6x   %-20s\r\n",i+uBase, vecdwRvaOfFuncs[i], vecdwFOAOfFuncs[i], nTemp ==size_t(-1)?"-": vecstrNames[nTemp].c_str());
        }
    }
    /// <summary>
    /// 通过函数名找到foa和rva
    /// </summary>
    /// <param name="strName">函数名</param>
    /// <returns><rva,foa></returns>
    std::pair<uint32_t, uint32_t> e_GetFunctionAddrByName(std::string strName)
    {
        size_t i;
        for (i = 0; i < vecstrNames.size(); ++i)
        {
            if (vecstrNames[i] == strName)
                break;
        }
        if (i == vecstrNames.size())
            return { -1,-1 };
        //找到名字在函数名表中的位置
        i = vecwOrds[i];//在序号表对应取出真实序号
        return { vecdwRvaOfFuncs[i],vecdwFOAOfFuncs[i] };
    }
    /// <summary>
    /// 通过导出序号找到FOA和rva
    /// </summary>
    /// <param name="uOrd">序号</param>
    /// <returns><rva,foa></returns>
    std::pair<uint32_t, uint32_t> e_GetFunctionAddrByOrdinals(uint32_t uOrd)
    {
        if(uOrd< uBase)
            return { -1,-1 };
        uOrd -= uBase;
        //算出在RVA表中的位置
        if (uOrd >= vecdwRvaOfFuncs.size())
            return { -1,-1 };
        //找到名字在函数名表中的位置
        return { vecdwRvaOfFuncs[uOrd],vecdwFOAOfFuncs[uOrd] };
    }
private:
    /// <summary>
    /// 通过导出序号找到函数名索引
    /// </summary>
    /// <param name="iPositon">导出序号</param>
    /// <returns>函数名索引</returns>
    size_t m_FindFuncName(size_t iPositon)
    {
        for (size_t i = 0; i < vecwOrds.size(); ++i)
        {
            if (vecwOrds[i] == iPositon)
                return i;
        }
        return -1;
    }
};

// 相关using定义
using mapImports  = std::unordered_map<std::wstring, std::vector<ImportData>>;
using mapBoundImports = std::unordered_map<std::wstring, BoundImportData>;
using vecSections = std::vector<IMAGE_SECTION_HEADER>;
using vecpSections = std::vector<PIMAGE_SECTION_HEADER>;
using vecExports  = ExportData;
#define ISNEIHE 0
/// <summary>
/// PE文件读取的类
/// </summary>
class PEImage
{
    friend class TransFileAndMem;
    using PCHDR32 = const IMAGE_NT_HEADERS32*;
    using PCHDR64 = const IMAGE_NT_HEADERS64*;
    
public:
    MYOBJECT_API PEImage( void );
    MYOBJECT_API ~PEImage( void );
    MYOBJECT_API PEImage( PEImage&& other ) = default;

    /// <summary>
    /// 装载文件到内存映像
    /// </summary>
    /// <param name="path">文件路径名字</param>
    /// <param name="skipActx">如果真 -不初始化激活上下文</param>
    /// <returns>状态码</returns>
    MYOBJECT_API NTSTATUS Load( const std::wstring& path, bool skipActx = false );
    /// <summary>
    /// 载入映像到内存区域 //可读可写
    /// </summary>
    /// <param name="path">文件名</param>
    /// <returns>状态码</returns>
    MYOBJECT_API NTSTATUS Load_Write(const std::wstring& path);
    /// <summary>
    /// 载入内存映像到内存区域中
    /// </summary>
    /// <param name="pData">内存区域</param>
    /// <param name="size">数据大小</param>
    /// <param name="plainData">如果为false 表示是PE的内存映像</param>
    /// <returns>状态码</returns>
    MYOBJECT_API NTSTATUS Load( void* pData, size_t size, bool plainData = true );
    /// <summary>
    /// 关闭文件后重新载入PE映像
    /// </summary>
    /// <returns>状态码</returns>
    MYOBJECT_API NTSTATUS Reload();
    /// <summary>
    /// 释放映射的文件映像或者内存映像
    /// </summary>
    /// <param name="temporary">是否保留文件路径以重新打开文件</param>
    MYOBJECT_API void Release( bool temporary = false );
    /// <summary>
    ///分析PE映像（PE头的信息）
    /// </summary>
    /// <returns>状态码</returns>
    MYOBJECT_API NTSTATUS Parse( void* pImageBase = nullptr );
    /// <summary>
    /// 展开显示目录表
    /// </summary>
    MYOBJECT_API void ShowDirectory();
    /// <summary>
    /// 或者映像的导入表
    /// </summary>
    /// <param name="useDelayed">映像使用延迟导入</param>
    /// <returns>导入表信息</returns>
    MYOBJECT_API mapImports& GetImports( bool useDelayed = false );
    /// <summary>
    /// 输出导出表信息
    /// </summary>
    /// <param name="imports">导入表map</param>
    MYOBJECT_API mapBoundImports& GetBoundPort();
    /// <summary>
    /// 显式导出表的信息
    /// </summary>
    /// <param name="imports">导出表表信息</param>
    /// <returns></returns>
    MYOBJECT_API void ShowImports(mapImports& imports);
    /// <summary>
    /// 显式绑定导入表
    /// </summary>
    /// <param name="boundimports"></param>
    /// <returns></returns>
    MYOBJECT_API void ShowBoundImport(mapBoundImports& boundimports);
    /// <summary>
    /// 获取导出表的所有的信息
    /// </summary>
    /// <param name="names">创建的存储export表信息的类</param>
    MYOBJECT_API void GetExports( vecExports& exports );
    /// <summary>
    /// 获取重定位表信息
    /// </summary>
    /// <param name="reloc"></param>
    /// <returns></returns>
    MYOBJECT_API void GetReloc(vecReloc& reloc);
    /// <summary>
    /// 检索映像TLS回调   
    /// 为目标映像重新设置回调
    /// </summary>
    /// <param name="targetBase">目标映像基址</param>
    /// <param name="result">是否找到回调</param>
    /// <returns>映像中TLS回调的数目</returns>
    MYOBJECT_API int GetTLSCallbacks( module_t targetBase, std::vector<ptr_t>& result ) const;

    /// <summary>
    /// 检索数据目录地址
    /// </summary>
    /// <param name="index">目录索引</param>
    /// <param name="keepRelative">保持地址相对于图像库<</param>
    /// <returns>目录表地址</returns>
    MYOBJECT_API uintptr_t DirectoryAddress( int index, AddressType type = VA ) const;


    /// <summary>
    /// 获取数据目录大小
    /// </summary>
    /// <param name="index">数据目录索引</param>
    /// <returns>数据目录大小</returns>
    MYOBJECT_API size_t DirectorySize( int index ) const;

    /// <summary>
    /// Resolve virtual memory address to physical file offset
    /// </summary>
    /// <param name="Rva">Memory address</param>
    /// <param name="type">Address type to return</param>
    /// <returns>Resolved address</returns>
    MYOBJECT_API uintptr_t ResolveRVAToVA( uintptr_t Rva, AddressType type = VA ) const;

    /// <summary>
    /// Get image path
    /// </summary>
    /// <returns>Image path</returns>
    MYOBJECT_API inline const std::wstring& path() const { return _imagePath; }

    /// <summary>
    /// Get image name
    /// </summary>
    /// <returns>Image name</returns>
    MYOBJECT_API inline std::wstring name() const { return Utils::StripPath( _imagePath ); }

    /// <summary>
    /// 获取内存映像的内存位置
    /// </summary>
    /// <returns>Image base</returns>
    MYOBJECT_API inline void* base() const { return _pFileBase; }

    /// <summary>
    /// 获取原始文件大小
    /// </summary>
    /// <returns>file size</returns>
    MYOBJECT_API inline uint32_t size() const { return _fileSize; }

    /// <summary>
    /// Get image base address
    /// </summary>
    /// <returns>Image base</returns>
    MYOBJECT_API inline module_t imageBase() const { return _imgBase; }

    /// <summary>
    /// Get image size in bytes
    /// </summary>
    /// <returns>Image size</returns>
    MYOBJECT_API inline uint32_t imageSize() const { return _imgSize; }

    /// <summary>
    /// Get size of image headers
    /// </summary>
    /// <returns>Size of image headers</returns>
    MYOBJECT_API inline size_t headersSize() const { return _hdrSize; }

    /// <summary>
    /// Get image entry point rebased to another image base
    /// </summary>
    /// <param name="base">New image base</param>
    /// <returns>New entry point address</returns>
    MYOBJECT_API inline ptr_t entryPoint( module_t base ) const { return ((_epRVA != 0) ? (_epRVA + base) : 0); };
    MYOBJECT_API inline ptr_t entryPoint() const { return ((_epRVA != 0) ? (_epRVA + _imgBase) : 0); };
    /// <summary>
    /// Get image sections
    /// </summary>
    /// <returns>Image sections</returns>
    MYOBJECT_API inline const vecSections& sections() const { return _sections; }
    MYOBJECT_API inline const vecpSections& pSections() const { return _pSections; }
    /// <summary>
    /// Check if image is an executable file and not a dll
    /// </summary>
    /// <returns>true if image is an *.exe</returns>
    MYOBJECT_API inline bool isExe() const { return _isExe; }

    /// <summary>
    /// Check if image is pure IL image
    /// </summary>
    /// <returns>true on success</returns>
    MYOBJECT_API inline bool pureIL() const  { return _isPureIL; }
    MYOBJECT_API inline int32_t ilFlagOffset() const { return _ILFlagOffset; }

    /// <summary>
    /// Get image type. 32/64 bit
    /// </summary>
    /// <returns>Image type</returns>
    MYOBJECT_API inline eModType mType() const { return _is64 ? mt_mod64 : mt_mod32; }

    /// <summary>
    /// Get activation context handle
    /// </summary>
    /// <returns>Actx handle</returns>
    MYOBJECT_API inline HANDLE actx() const { return _hctx; }

    /// <summary>
    /// true if image is mapped as plain data file
    /// </summary>
    /// <returns>true if mapped as plain data file, false if mapped as image</returns>
    MYOBJECT_API inline bool isPlainData() const { return _isPlainData; }

    /// <summary>
    /// Get manifest resource ID
    /// </summary>
    /// <returns>Manifest resource ID</returns>
    MYOBJECT_API inline int manifestID() const { return _manifestIdx; }

    /// <summary>
    /// Get image subsystem
    /// </summary>
    /// <returns>Image subsystem</returns>
    MYOBJECT_API inline uint32_t subsystem() const { return _subsystem; }

    /// <summary>
    /// Get manifest resource file
    /// </summary>
    /// <returns>Manifest resource file</returns>
    MYOBJECT_API inline const std::wstring& manifestFile() const { return _manifestPath; }

    /// <summary>
    /// If true - no actual PE file available on disk
    /// </summary>
    /// <returns>Flag</returns>
    MYOBJECT_API inline bool noPhysFile() const { return _noFile; }

    /// <summary>
    /// DllCharacteristics field of header
    /// </summary>
    /// <returns>DllCharacteristics</returns>
    MYOBJECT_API inline uint32_t DllCharacteristics() const { return _DllCharacteristics; }


private:
    /// <summary>
    /// Prepare activation context
    /// </summary>
    /// <param name="filepath">Path to PE file. If nullptr - manifest is extracted from memory to disk</param>
    /// <returns>状态码</returns>
    NTSTATUS PrepareACTX( const wchar_t* filepath = nullptr );

    /// <summary>
    /// Get manifest from image data
    /// </summary>
    /// <param name="size">Manifest size</param>
    /// <param name="manifestID">Mmanifest ID</param>
    /// <returns>Manifest data</returns>
    void* GetManifest( uint32_t& size, int32_t& manifestID );

private:
    Handle      _hFile;                         // 目标文件句柄
    Handle      _hMapping;                      // 内存映射文件句柄
    Mapping     _pFileBase;                     // 内存映像文件的基址
    uint32_t    _fileSize;                      // pe文件原来的大小
    bool        _isPlainData = false;           // 是否非内存平坦文件
    bool        _is64 = false;                  // 镜像是64位pe？
    bool        _isExe = false;                 // 是否是exe文件
    bool        _isPureIL = false;              // Pure IL image
    bool        _noFile = false;                // 标识是内存映像导入的内存 没有文件
    PCHDR32     _pImageHdr32 = nullptr;         // PE头信息
    PCHDR64     _pImageHdr64 = nullptr;         // PE头信息
    ptr_t       _imgBase = 0;                   // 在内存中的基址
    uint32_t    _imgSize = 0;                   // 映像大小
    uint32_t    _epRVA = 0;                     // 入口点的RVA
    uint32_t    _hdrSize = 0;                   // 头的大小
    ACtxHandle  _hctx;                          // 激活上下文
    int32_t     _manifestIdx = 0;               // 清单资源ID
    uint32_t    _subsystem = 0;                 // 映像子系统
    int32_t     _ILFlagOffset = 0;              // Offset of pure IL flag
    uint32_t    _DllCharacteristics = 0;        // DllCharacteristics 文件属性标识
#if 0
    #define IMAGE_SIZEOF_SHORT_NAME 8
    typedef struct _IMAGE_SECTION_HEADER { //节属性
        BYTE    Name[IMAGE_SIZEOF_SHORT_NAME]; //节的名字 正常是Ascii码 但是可以写满（我们需要自己去处理）
        union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
        } Misc; //双字  是该节在没有对齐前的真实尺寸，该值可以不准确
        DWORD   VirtualAddress;//对应节的RVA,
        DWORD   SizeOfRawData;//在文件中对齐的大小
        DWORD   PointerToRawData;//节区在文件中的偏移
        DWORD   PointerToRelocations; //在OBJ文件中使用 对exe无意义
        DWORD   PointerToLinenumbers; //行号表的尾置 调试的时候使用
        WORD    NumberOfRelocations; //在OBJ文件中使用 对exe无意义
        WORD    NumberOfLinenumbers;//行号表中行号的数量，调试的时候使用
        DWORD   Characteristics;
        #if 0 //属性值
        #define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.（节包含可执行代码）
        #define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.（节包含已初始化数据）
        #define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.（节包含位初始化数据）
        #define IMAGE_SCN_LNK_INFO                   0x00000200  // Section contains comments or some other type of information.
        #define IMAGE_SCN_LNK_REMOVE                 0x00000800  // Section contents will not become part of image.
        #define IMAGE_SCN_LNK_COMDAT                 0x00001000  // Section contents comdat.
        #define IMAGE_SCN_NO_DEFER_SPEC_EXC          0x00004000  // Reset speculative exceptions handling bits in the TLB entries for this section.
        #define IMAGE_SCN_GPREL                      0x00008000  // Section content can be accessed relative to GP
        #define IMAGE_SCN_ALIGN_16BYTES              0x00500000  // Default alignment if no others are specified.
        #define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  // Section contains extended relocations.
        #define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  // Section can be discarded.
        #define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  // Section is not cachable.
        #define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  // Section is not pageable.
        #define IMAGE_SCN_MEM_SHARED                 0x10000000  // Section is shareable.（该块位共享块）
        #define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.（该块可执行）
        #define IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.（该块可读）
        #define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.（该块可写）
        #endif //属性值

       
    } IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;
#endif
    //using vecSections = std::vector<IMAGE_SECTION_HEADER>;
    vecSections _sections;                      // 节表的信息
    vecpSections _pSections;                    // 节表指针
    mapImports  _imports;                       // 导入表
    mapImports  _delayImports;                  // 延迟导入表
    mapBoundImports _boundimport;               // 绑定导入表

    std::wstring _imagePath;                    // 映像的文件路径
    std::wstring _manifestPath;                 // 映像的manifest路径

private:
//1.DOS 头
    int16_t     *p_e_magic;                     //"MZ标志"用于判断是否为可执行文件
    uint32_t    *p_e_lfanew;                    //PE头相对于文件的偏移，用于定位PE文件
//2.标准PE头
    uint16_t    *p_Machine;                     //程序运行的CPU型号：0x0任何处理器 /0x14C 386及其后续处理器
    uint16_t    *p_NumberOfSections;            //文件中存在的节的总数，如果要新增节或者合并节，就要修改这个值
                                                //Windows加载器限制节的最大数目为96
    uint32_t    *p_TimeDateStamp;               //UTC时间1970年1月1日00:00起的总秒数的低32位，它指出文件何时被创建。
    uint16_t    *p_SizeOfOptionalHeader;        //可选PE头的大小(可自定义)。这个大小在32位和64位文件中是不同的。对于32位文件来说，它是224(E0)；对于64位文件来说，它是240(F0)。
    uint16_t    *p_FillCharacteristics;         //指示文件属性的标志      0x10F表示可执行文件
//3.可选PE头
//3.1 第一部分 32位pe 96字节 64位pe112字节

    uint16_t    *p_Magic;                       //文件类型：0x10B表明这是一个32位镜像文件。    0x107表明这是一个ROM镜像。         0x20B表明这是一个64位镜像文件。
    uint8_t     *p_MajorLinkerVersion;          //链接器的主版本号。
    uint8_t     *p_MinorLinkerVersion;          //链接器的次版本号。
    uint32_t    *p_SizeOfCode;                  //一般放在“.text”节里。如果有多个代码节的话，它是所有代码节的和。必须是FileAlignment的整数倍，是在文件里的大小。 编译器填的，没有用
    uint32_t    *p_SizeOfInitializedData;       //已初始化数大小,已初始化数一般放在“.data”节里。如果有多个这样的节话，它是所有这些节的和。必须是FileAlignment的整数倍，是在文件里的大小。编译器填的，没有用
    uint32_t    *p_SizeOfUninitializedData;     //未初始化数大小,一般放在“.bss”节里。如果有多个这样的节话，它是所有这些节的和。必须是FileAlignment的整数倍，是在文件里的大小。编译器填的，没有用
    uint32_t    *p_AddressOfEntryPoint;         //当可执行文件被加载进内存时其入口点RVA。对于一般程序镜像来说，它就是启动地址。为0则从ImageBase开始执行。对于dll文件是可选的。
    uint32_t    *p_BaseOfCode;                  //当镜像被加载进内存时代码节的开头RVA。必须是SectionAlignment的整数倍。
    //32 64 不一样
    uint32_t    *p_BaseOfData_32;               //当镜像被加载进内存时数据节的开头RVA。（在64位文件中此处被并入紧随其后的ImageBase中。）必须是SectionAlignment的整数倍
    uint32_t    *p_ImageBase_32;                //当加载进内存时镜像的第1个字节的首选地址。它必须是64K的倍数。DLL默认是10000000H。Windows CE 的EXE默认是00010000H。Windows 系列的EXE默认是00400000H。
    uint64_t    *p_ImageBase_64;                //
    
    uint32_t    *p_SectionAlignment;            //当加载进内存时节的对齐值（以字节计）。它必须≥FileAlignment。默认是相应系统的页面大小。
    uint32_t    *p_FileAlignment;               //用来对齐镜像文件的节中的原始数据的对齐因子（以字节计）。它应该是界于512和64K之间的2的幂（包括这两个边界值）。默认是512。如果SectionAlignment小于相应系统的页面大小，那么FileAlignment必须与SectionAlignment相等。
    uint16_t    *p_MajorOperatingSystemVersion; //主系统的主版本号
    uint16_t    *p_MinorOperatingSystemVersion; //主系统的次版本号
    uint16_t    *p_MajorImageVersion;             //镜像的主版本号
    uint16_t    *p_MinorImageVersion;             //镜像的次版本号	
    uint16_t    *p_MajorSubsystemVersion;         //子系统的主版本号
    uint16_t    *p_MinorSubsystemVersion;         //子系统的次版本号
    uint16_t    *p_Win32VersionValue;             //保留，必须为0
    uint32_t    *p_SizeOfImage;                   //镜像大小	当镜像被加载进内存时的大小，包括所有的文件头。向上舍入为SectionAlignment的倍数。
    uint32_t    *p_SizeOfHeaders;                 //头大小 所有头的总大小，向上舍入为FileAlignment的倍数。可以以此值作为PE文件第一节的文件偏移量。
    uint32_t    *p_CheckSum;                      //校验和       镜像文件的校验和。计算校验和的算法被合并到了Imagehlp.DLL 中。以下程序在加载时被校验以确定其是否合法：所有的驱动程序、任何在引导时被加载的DLL以及加载进关键Windows进程中的DLL。
    uint16_t    *p_Subsystem;                     //子系统类型 运行此镜像所需的子系统。
    uint16_t    *p_DllCharacteristics;            //Dll标识

    uint32_t    *p_SizeOfStackReserve_32;         //堆栈保留大小,最大栈大小。CPU的堆栈。默认是1MB。
    uint32_t    *p_SizeOfStackCommit_32;          //初始提交的堆栈大小。默认是4KB。
    uint32_t    *p_SizeOfHeapReserve_32;          //最大堆大小。编译器分配的。默认是1MB。
    uint32_t    *p_SizeOfHeapCommit_32;           //初始提交的局部堆空间大小。默认是4KB。

    uint64_t    *p_SizeOfStackReserve_64;         //堆栈保留大小,最大栈大小。CPU的堆栈。默认是1MB。
    uint64_t    *p_SizeOfStackCommit_64;          //初始提交的堆栈大小。默认是4KB。
    uint64_t    *p_SizeOfHeapReserve_64;          //最大堆大小。编译器分配的。默认是1MB。
    uint64_t    *p_SizeOfHeapCommit_64;           //初始提交的局部堆空间大小。默认是4KB。

    uint32_t    *p_LoaderFlags;                   //保留，必须为0
    uint32_t    *p_NumberOfRvaAndSizes;           //数据目录项的个数。由于以前发行的Windows NT的原因，它只能为16。










};

}
}
