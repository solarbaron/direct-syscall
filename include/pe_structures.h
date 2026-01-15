#pragma once

#include <cstdint>

// PE Format structures - manually defined to avoid Windows.h dependency
// These match the official PE/COFF specification

namespace pe {

// DOS Header
struct DOS_HEADER {
    uint16_t e_magic;      // Magic number (MZ = 0x5A4D)
    uint16_t e_cblp;       // Bytes on last page of file
    uint16_t e_cp;         // Pages in file
    uint16_t e_crlc;       // Relocations
    uint16_t e_cparhdr;    // Size of header in paragraphs
    uint16_t e_minalloc;   // Minimum extra paragraphs needed
    uint16_t e_maxalloc;   // Maximum extra paragraphs needed
    uint16_t e_ss;         // Initial (relative) SS value
    uint16_t e_sp;         // Initial SP value
    uint16_t e_csum;       // Checksum
    uint16_t e_ip;         // Initial IP value
    uint16_t e_cs;         // Initial (relative) CS value
    uint16_t e_lfarlc;     // File address of relocation table
    uint16_t e_ovno;       // Overlay number
    uint16_t e_res[4];     // Reserved words
    uint16_t e_oemid;      // OEM identifier
    uint16_t e_oeminfo;    // OEM information
    uint16_t e_res2[10];   // Reserved words
    int32_t  e_lfanew;     // File address of new exe header (PE header offset)
};

// File Header (COFF Header)
struct FILE_HEADER {
    uint16_t Machine;              // Target machine type
    uint16_t NumberOfSections;     // Number of sections
    uint32_t TimeDateStamp;        // Time stamp
    uint32_t PointerToSymbolTable; // File offset of symbol table
    uint32_t NumberOfSymbols;      // Number of symbols
    uint16_t SizeOfOptionalHeader; // Size of optional header
    uint16_t Characteristics;      // Characteristics flags
};

// Data Directory entry
struct DATA_DIRECTORY {
    uint32_t VirtualAddress;  // RVA of the data
    uint32_t Size;            // Size of the data
};

// Optional Header (64-bit)
struct OPTIONAL_HEADER_64 {
    uint16_t Magic;                   // 0x20b for PE32+
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    DATA_DIRECTORY DataDirectory[16];  // Data directories
};

// NT Headers (64-bit)
struct NT_HEADERS_64 {
    uint32_t Signature;            // PE signature (0x00004550 = "PE\0\0")
    FILE_HEADER FileHeader;
    OPTIONAL_HEADER_64 OptionalHeader;
};

// Section Header
struct SECTION_HEADER {
    char     Name[8];              // Section name
    uint32_t VirtualSize;          // Virtual size
    uint32_t VirtualAddress;       // RVA
    uint32_t SizeOfRawData;        // Size of raw data
    uint32_t PointerToRawData;     // File pointer to raw data
    uint32_t PointerToRelocations; // File pointer to relocations
    uint32_t PointerToLinenumbers; // File pointer to line numbers
    uint16_t NumberOfRelocations;  // Number of relocations
    uint16_t NumberOfLinenumbers;  // Number of line numbers
    uint32_t Characteristics;      // Section characteristics
};

// Export Directory
struct EXPORT_DIRECTORY {
    uint32_t Characteristics;      // Reserved, must be 0
    uint32_t TimeDateStamp;        // Time stamp
    uint16_t MajorVersion;         // Major version
    uint16_t MinorVersion;         // Minor version
    uint32_t Name;                 // RVA of the DLL name
    uint32_t Base;                 // Ordinal base
    uint32_t NumberOfFunctions;    // Number of functions
    uint32_t NumberOfNames;        // Number of names
    uint32_t AddressOfFunctions;   // RVA of function addresses
    uint32_t AddressOfNames;       // RVA of name pointers
    uint32_t AddressOfNameOrdinals;// RVA of ordinals
};

// Constants
constexpr uint16_t DOS_MAGIC = 0x5A4D;           // "MZ"
constexpr uint32_t NT_SIGNATURE = 0x00004550;    // "PE\0\0"
constexpr uint16_t OPTIONAL_HDR64_MAGIC = 0x20b; // PE32+ (64-bit)
constexpr uint16_t MACHINE_AMD64 = 0x8664;       // x64

// Data directory indices
constexpr int DIRECTORY_ENTRY_EXPORT = 0;

} // namespace pe
