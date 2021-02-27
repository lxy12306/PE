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
    RVA,    // ��������ַƫ��
    VA,     // ��ʵ��ַƫ�ƣ���һ���������ַ Ҳ�п������ļ���ַ��
    FOA,    // ����ļ���ַƫ��
};

/// <summary>
/// �ض�λ�����Ϣ
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
            printf("�ض�λ��:<%8x>,��Ҫ�ض�λ:<%8x>********\r\n", vecRelocData[i].PageRVA, vecRelocData[i].size()-1);
            for (size_t j = 0; j < vecRelocData[i].size()-1; ++j)
            {
                auto ij = vecRelocData[i][j];
                printf("����:<%x>,RVA:<%x>\r\n", ij.first, ij.second);
            }
        }
    }
private:
    std::vector<RelocData> vecRelocData;
};

/// <summary>
/// ��������Ϣ
/// </summary>
struct ImportData
{
    std::string importName;     // Function name
    uintptr_t ptrRVA;            // Function pointer RVA in
    WORD importOrdinal;         // Function ordinal
    bool importByOrd;           // Function is imported by ordinal
};

/// <summary>
/// �󶨵�������Ϣ
/// </summary>
struct BoundImportData
{
    struct BoundForwaredRefData
    {
        uint32_t uTimeDateStamp; //��DLL��Ҫ�����dll��ʱ���
        std::string strDllName;//��DLL��Ҫ�����dll������
        BoundForwaredRefData() :uTimeDateStamp(0), strDllName() {}
        BoundForwaredRefData(uint32_t u, std::string str):uTimeDateStamp(u), strDllName(str){}
    };

    uint32_t uTimeDateStamp; //��ʵ��ʱ���
    std::vector<BoundForwaredRefData> vecRef; //��DLL��Ҫ���������DLL
    BoundImportData(uint32_t u1,uint16_t u2):uTimeDateStamp(u1), vecRef(std::vector<BoundForwaredRefData>(u2)){}
};

/// <summary>
/// �����������
/// </summary>
struct ExportData
{
    std::string strName;//����������
    uint32_t uBase;//��ŵ�����ʼ���
    uint32_t uFoa;//������Foa
    uint32_t uRva;//������RVA
    uint32_t uFoaDerictory;//Ŀ¼���FOA


    std::vector<std::string> vecstrNames;//��������������
    std::vector<uint16_t>   vecwOrds;//�����ֵ����ĵ������������
    std::vector<uint32_t> vecdwRvaOfFuncs;//����������RVA
    std::vector<uint32_t> vecdwFOAOfFuncs;//����������FOA
    /// <summary>
    /// �����������
    /// </summary>
    /// <param name="pied"></param>
    /// <summary>
    /// �������
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
        printf("����������Ϊ:%s\r\n", strName.c_str());
        printf("���--------RVA------FOA------������\r\n");
        for (size_t i = 0; i < vecdwFOAOfFuncs.size(); ++i)
        {
            size_t nTemp = m_FindFuncName(i);
            if (vecdwRvaOfFuncs[i] != 0)
                printf("%-4hd        %-6x   %-6x   %-20s\r\n",i+uBase, vecdwRvaOfFuncs[i], vecdwFOAOfFuncs[i], nTemp ==size_t(-1)?"-": vecstrNames[nTemp].c_str());
        }
    }
    /// <summary>
    /// ͨ���������ҵ�foa��rva
    /// </summary>
    /// <param name="strName">������</param>
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
        //�ҵ������ں��������е�λ��
        i = vecwOrds[i];//����ű��Ӧȡ����ʵ���
        return { vecdwRvaOfFuncs[i],vecdwFOAOfFuncs[i] };
    }
    /// <summary>
    /// ͨ����������ҵ�FOA��rva
    /// </summary>
    /// <param name="uOrd">���</param>
    /// <returns><rva,foa></returns>
    std::pair<uint32_t, uint32_t> e_GetFunctionAddrByOrdinals(uint32_t uOrd)
    {
        if(uOrd< uBase)
            return { -1,-1 };
        uOrd -= uBase;
        //�����RVA���е�λ��
        if (uOrd >= vecdwRvaOfFuncs.size())
            return { -1,-1 };
        //�ҵ������ں��������е�λ��
        return { vecdwRvaOfFuncs[uOrd],vecdwFOAOfFuncs[uOrd] };
    }
private:
    /// <summary>
    /// ͨ����������ҵ�����������
    /// </summary>
    /// <param name="iPositon">�������</param>
    /// <returns>����������</returns>
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

// ���using����
using mapImports  = std::unordered_map<std::wstring, std::vector<ImportData>>;
using mapBoundImports = std::unordered_map<std::wstring, BoundImportData>;
using vecSections = std::vector<IMAGE_SECTION_HEADER>;
using vecpSections = std::vector<PIMAGE_SECTION_HEADER>;
using vecExports  = ExportData;
#define ISNEIHE 0
/// <summary>
/// PE�ļ���ȡ����
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
    /// װ���ļ����ڴ�ӳ��
    /// </summary>
    /// <param name="path">�ļ�·������</param>
    /// <param name="skipActx">����� -����ʼ������������</param>
    /// <returns>״̬��</returns>
    MYOBJECT_API NTSTATUS Load( const std::wstring& path, bool skipActx = false );
    /// <summary>
    /// ����ӳ���ڴ����� //�ɶ���д
    /// </summary>
    /// <param name="path">�ļ���</param>
    /// <returns>״̬��</returns>
    MYOBJECT_API NTSTATUS Load_Write(const std::wstring& path);
    /// <summary>
    /// �����ڴ�ӳ���ڴ�������
    /// </summary>
    /// <param name="pData">�ڴ�����</param>
    /// <param name="size">���ݴ�С</param>
    /// <param name="plainData">���Ϊfalse ��ʾ��PE���ڴ�ӳ��</param>
    /// <returns>״̬��</returns>
    MYOBJECT_API NTSTATUS Load( void* pData, size_t size, bool plainData = true );
    /// <summary>
    /// �ر��ļ�����������PEӳ��
    /// </summary>
    /// <returns>״̬��</returns>
    MYOBJECT_API NTSTATUS Reload();
    /// <summary>
    /// �ͷ�ӳ����ļ�ӳ������ڴ�ӳ��
    /// </summary>
    /// <param name="temporary">�Ƿ����ļ�·�������´��ļ�</param>
    MYOBJECT_API void Release( bool temporary = false );
    /// <summary>
    ///����PEӳ��PEͷ����Ϣ��
    /// </summary>
    /// <returns>״̬��</returns>
    MYOBJECT_API NTSTATUS Parse( void* pImageBase = nullptr );
    /// <summary>
    /// չ����ʾĿ¼��
    /// </summary>
    MYOBJECT_API void ShowDirectory();
    /// <summary>
    /// ����ӳ��ĵ����
    /// </summary>
    /// <param name="useDelayed">ӳ��ʹ���ӳٵ���</param>
    /// <returns>�������Ϣ</returns>
    MYOBJECT_API mapImports& GetImports( bool useDelayed = false );
    /// <summary>
    /// �����������Ϣ
    /// </summary>
    /// <param name="imports">�����map</param>
    MYOBJECT_API mapBoundImports& GetBoundPort();
    /// <summary>
    /// ��ʽ���������Ϣ
    /// </summary>
    /// <param name="imports">���������Ϣ</param>
    /// <returns></returns>
    MYOBJECT_API void ShowImports(mapImports& imports);
    /// <summary>
    /// ��ʽ�󶨵����
    /// </summary>
    /// <param name="boundimports"></param>
    /// <returns></returns>
    MYOBJECT_API void ShowBoundImport(mapBoundImports& boundimports);
    /// <summary>
    /// ��ȡ����������е���Ϣ
    /// </summary>
    /// <param name="names">�����Ĵ洢export����Ϣ����</param>
    MYOBJECT_API void GetExports( vecExports& exports );
    /// <summary>
    /// ��ȡ�ض�λ����Ϣ
    /// </summary>
    /// <param name="reloc"></param>
    /// <returns></returns>
    MYOBJECT_API void GetReloc(vecReloc& reloc);
    /// <summary>
    /// ����ӳ��TLS�ص�   
    /// ΪĿ��ӳ���������ûص�
    /// </summary>
    /// <param name="targetBase">Ŀ��ӳ���ַ</param>
    /// <param name="result">�Ƿ��ҵ��ص�</param>
    /// <returns>ӳ����TLS�ص�����Ŀ</returns>
    MYOBJECT_API int GetTLSCallbacks( module_t targetBase, std::vector<ptr_t>& result ) const;

    /// <summary>
    /// ��������Ŀ¼��ַ
    /// </summary>
    /// <param name="index">Ŀ¼����</param>
    /// <param name="keepRelative">���ֵ�ַ�����ͼ���<</param>
    /// <returns>Ŀ¼���ַ</returns>
    MYOBJECT_API uintptr_t DirectoryAddress( int index, AddressType type = VA ) const;


    /// <summary>
    /// ��ȡ����Ŀ¼��С
    /// </summary>
    /// <param name="index">����Ŀ¼����</param>
    /// <returns>����Ŀ¼��С</returns>
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
    /// ��ȡ�ڴ�ӳ����ڴ�λ��
    /// </summary>
    /// <returns>Image base</returns>
    MYOBJECT_API inline void* base() const { return _pFileBase; }

    /// <summary>
    /// ��ȡԭʼ�ļ���С
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
    /// <returns>״̬��</returns>
    NTSTATUS PrepareACTX( const wchar_t* filepath = nullptr );

    /// <summary>
    /// Get manifest from image data
    /// </summary>
    /// <param name="size">Manifest size</param>
    /// <param name="manifestID">Mmanifest ID</param>
    /// <returns>Manifest data</returns>
    void* GetManifest( uint32_t& size, int32_t& manifestID );

private:
    Handle      _hFile;                         // Ŀ���ļ����
    Handle      _hMapping;                      // �ڴ�ӳ���ļ����
    Mapping     _pFileBase;                     // �ڴ�ӳ���ļ��Ļ�ַ
    uint32_t    _fileSize;                      // pe�ļ�ԭ���Ĵ�С
    bool        _isPlainData = false;           // �Ƿ���ڴ�ƽ̹�ļ�
    bool        _is64 = false;                  // ������64λpe��
    bool        _isExe = false;                 // �Ƿ���exe�ļ�
    bool        _isPureIL = false;              // Pure IL image
    bool        _noFile = false;                // ��ʶ���ڴ�ӳ������ڴ� û���ļ�
    PCHDR32     _pImageHdr32 = nullptr;         // PEͷ��Ϣ
    PCHDR64     _pImageHdr64 = nullptr;         // PEͷ��Ϣ
    ptr_t       _imgBase = 0;                   // ���ڴ��еĻ�ַ
    uint32_t    _imgSize = 0;                   // ӳ���С
    uint32_t    _epRVA = 0;                     // ��ڵ��RVA
    uint32_t    _hdrSize = 0;                   // ͷ�Ĵ�С
    ACtxHandle  _hctx;                          // ����������
    int32_t     _manifestIdx = 0;               // �嵥��ԴID
    uint32_t    _subsystem = 0;                 // ӳ����ϵͳ
    int32_t     _ILFlagOffset = 0;              // Offset of pure IL flag
    uint32_t    _DllCharacteristics = 0;        // DllCharacteristics �ļ����Ա�ʶ
#if 0
    #define IMAGE_SIZEOF_SHORT_NAME 8
    typedef struct _IMAGE_SECTION_HEADER { //������
        BYTE    Name[IMAGE_SIZEOF_SHORT_NAME]; //�ڵ����� ������Ascii�� ���ǿ���д����������Ҫ�Լ�ȥ����
        union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
        } Misc; //˫��  �Ǹý���û�ж���ǰ����ʵ�ߴ磬��ֵ���Բ�׼ȷ
        DWORD   VirtualAddress;//��Ӧ�ڵ�RVA,
        DWORD   SizeOfRawData;//���ļ��ж���Ĵ�С
        DWORD   PointerToRawData;//�������ļ��е�ƫ��
        DWORD   PointerToRelocations; //��OBJ�ļ���ʹ�� ��exe������
        DWORD   PointerToLinenumbers; //�кű��β�� ���Ե�ʱ��ʹ��
        WORD    NumberOfRelocations; //��OBJ�ļ���ʹ�� ��exe������
        WORD    NumberOfLinenumbers;//�кű����кŵ����������Ե�ʱ��ʹ��
        DWORD   Characteristics;
        #if 0 //����ֵ
        #define IMAGE_SCN_CNT_CODE                   0x00000020  // Section contains code.���ڰ�����ִ�д��룩
        #define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  // Section contains initialized data.���ڰ����ѳ�ʼ�����ݣ�
        #define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  // Section contains uninitialized data.���ڰ���λ��ʼ�����ݣ�
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
        #define IMAGE_SCN_MEM_SHARED                 0x10000000  // Section is shareable.���ÿ�λ����飩
        #define IMAGE_SCN_MEM_EXECUTE                0x20000000  // Section is executable.���ÿ��ִ�У�
        #define IMAGE_SCN_MEM_READ                   0x40000000  // Section is readable.���ÿ�ɶ���
        #define IMAGE_SCN_MEM_WRITE                  0x80000000  // Section is writeable.���ÿ��д��
        #endif //����ֵ

       
    } IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;
#endif
    //using vecSections = std::vector<IMAGE_SECTION_HEADER>;
    vecSections _sections;                      // �ڱ����Ϣ
    vecpSections _pSections;                    // �ڱ�ָ��
    mapImports  _imports;                       // �����
    mapImports  _delayImports;                  // �ӳٵ����
    mapBoundImports _boundimport;               // �󶨵����

    std::wstring _imagePath;                    // ӳ����ļ�·��
    std::wstring _manifestPath;                 // ӳ���manifest·��

private:
//1.DOS ͷ
    int16_t     *p_e_magic;                     //"MZ��־"�����ж��Ƿ�Ϊ��ִ���ļ�
    uint32_t    *p_e_lfanew;                    //PEͷ������ļ���ƫ�ƣ����ڶ�λPE�ļ�
//2.��׼PEͷ
    uint16_t    *p_Machine;                     //�������е�CPU�ͺţ�0x0�κδ����� /0x14C 386�������������
    uint16_t    *p_NumberOfSections;            //�ļ��д��ڵĽڵ����������Ҫ�����ڻ��ߺϲ��ڣ���Ҫ�޸����ֵ
                                                //Windows���������ƽڵ������ĿΪ96
    uint32_t    *p_TimeDateStamp;               //UTCʱ��1970��1��1��00:00����������ĵ�32λ����ָ���ļ���ʱ��������
    uint16_t    *p_SizeOfOptionalHeader;        //��ѡPEͷ�Ĵ�С(���Զ���)�������С��32λ��64λ�ļ����ǲ�ͬ�ġ�����32λ�ļ���˵������224(E0)������64λ�ļ���˵������240(F0)��
    uint16_t    *p_FillCharacteristics;         //ָʾ�ļ����Եı�־      0x10F��ʾ��ִ���ļ�
//3.��ѡPEͷ
//3.1 ��һ���� 32λpe 96�ֽ� 64λpe112�ֽ�

    uint16_t    *p_Magic;                       //�ļ����ͣ�0x10B��������һ��32λ�����ļ���    0x107��������һ��ROM����         0x20B��������һ��64λ�����ļ���
    uint8_t     *p_MajorLinkerVersion;          //�����������汾�š�
    uint8_t     *p_MinorLinkerVersion;          //�������Ĵΰ汾�š�
    uint32_t    *p_SizeOfCode;                  //һ����ڡ�.text���������ж������ڵĻ����������д���ڵĺ͡�������FileAlignment���������������ļ���Ĵ�С�� ��������ģ�û����
    uint32_t    *p_SizeOfInitializedData;       //�ѳ�ʼ������С,�ѳ�ʼ����һ����ڡ�.data���������ж�������Ľڻ�������������Щ�ڵĺ͡�������FileAlignment���������������ļ���Ĵ�С����������ģ�û����
    uint32_t    *p_SizeOfUninitializedData;     //δ��ʼ������С,һ����ڡ�.bss���������ж�������Ľڻ�������������Щ�ڵĺ͡�������FileAlignment���������������ļ���Ĵ�С����������ģ�û����
    uint32_t    *p_AddressOfEntryPoint;         //����ִ���ļ������ؽ��ڴ�ʱ����ڵ�RVA������һ���������˵��������������ַ��Ϊ0���ImageBase��ʼִ�С�����dll�ļ��ǿ�ѡ�ġ�
    uint32_t    *p_BaseOfCode;                  //�����񱻼��ؽ��ڴ�ʱ����ڵĿ�ͷRVA��������SectionAlignment����������
    //32 64 ��һ��
    uint32_t    *p_BaseOfData_32;               //�����񱻼��ؽ��ڴ�ʱ���ݽڵĿ�ͷRVA������64λ�ļ��д˴��������������ImageBase�С���������SectionAlignment��������
    uint32_t    *p_ImageBase_32;                //�����ؽ��ڴ�ʱ����ĵ�1���ֽڵ���ѡ��ַ����������64K�ı�����DLLĬ����10000000H��Windows CE ��EXEĬ����00010000H��Windows ϵ�е�EXEĬ����00400000H��
    uint64_t    *p_ImageBase_64;                //
    
    uint32_t    *p_SectionAlignment;            //�����ؽ��ڴ�ʱ�ڵĶ���ֵ�����ֽڼƣ����������FileAlignment��Ĭ������Ӧϵͳ��ҳ���С��
    uint32_t    *p_FileAlignment;               //�������뾵���ļ��Ľ��е�ԭʼ���ݵĶ������ӣ����ֽڼƣ�����Ӧ���ǽ���512��64K֮���2���ݣ������������߽�ֵ����Ĭ����512�����SectionAlignmentС����Ӧϵͳ��ҳ���С����ôFileAlignment������SectionAlignment��ȡ�
    uint16_t    *p_MajorOperatingSystemVersion; //��ϵͳ�����汾��
    uint16_t    *p_MinorOperatingSystemVersion; //��ϵͳ�Ĵΰ汾��
    uint16_t    *p_MajorImageVersion;             //��������汾��
    uint16_t    *p_MinorImageVersion;             //����Ĵΰ汾��	
    uint16_t    *p_MajorSubsystemVersion;         //��ϵͳ�����汾��
    uint16_t    *p_MinorSubsystemVersion;         //��ϵͳ�Ĵΰ汾��
    uint16_t    *p_Win32VersionValue;             //����������Ϊ0
    uint32_t    *p_SizeOfImage;                   //�����С	�����񱻼��ؽ��ڴ�ʱ�Ĵ�С���������е��ļ�ͷ����������ΪSectionAlignment�ı�����
    uint32_t    *p_SizeOfHeaders;                 //ͷ��С ����ͷ���ܴ�С����������ΪFileAlignment�ı����������Դ�ֵ��ΪPE�ļ���һ�ڵ��ļ�ƫ������
    uint32_t    *p_CheckSum;                      //У���       �����ļ���У��͡�����У��͵��㷨���ϲ�����Imagehlp.DLL �С����³����ڼ���ʱ��У����ȷ�����Ƿ�Ϸ������е����������κ�������ʱ�����ص�DLL�Լ����ؽ��ؼ�Windows�����е�DLL��
    uint16_t    *p_Subsystem;                     //��ϵͳ���� ���д˾����������ϵͳ��
    uint16_t    *p_DllCharacteristics;            //Dll��ʶ

    uint32_t    *p_SizeOfStackReserve_32;         //��ջ������С,���ջ��С��CPU�Ķ�ջ��Ĭ����1MB��
    uint32_t    *p_SizeOfStackCommit_32;          //��ʼ�ύ�Ķ�ջ��С��Ĭ����4KB��
    uint32_t    *p_SizeOfHeapReserve_32;          //���Ѵ�С������������ġ�Ĭ����1MB��
    uint32_t    *p_SizeOfHeapCommit_32;           //��ʼ�ύ�ľֲ��ѿռ��С��Ĭ����4KB��

    uint64_t    *p_SizeOfStackReserve_64;         //��ջ������С,���ջ��С��CPU�Ķ�ջ��Ĭ����1MB��
    uint64_t    *p_SizeOfStackCommit_64;          //��ʼ�ύ�Ķ�ջ��С��Ĭ����4KB��
    uint64_t    *p_SizeOfHeapReserve_64;          //���Ѵ�С������������ġ�Ĭ����1MB��
    uint64_t    *p_SizeOfHeapCommit_64;           //��ʼ�ύ�ľֲ��ѿռ��С��Ĭ����4KB��

    uint32_t    *p_LoaderFlags;                   //����������Ϊ0
    uint32_t    *p_NumberOfRvaAndSizes;           //����Ŀ¼��ĸ�����������ǰ���е�Windows NT��ԭ����ֻ��Ϊ16��










};

}
}
