#include "pe_parser.h"
#include <fstream>
#include <iostream>
#include <cstring>

namespace syscall_detector {

PEParser::PEParser()
    : m_loaded(false)
    , m_is64bit(false)
    , m_dos_header(nullptr)
    , m_nt_headers(nullptr)
    , m_export_dir(nullptr)
    , m_export_dir_rva(0)
{
}

PEParser::~PEParser() = default;

bool PEParser::load(const std::string& filepath) {
    m_filepath = filepath;
    m_loaded = false;
    m_file_data.clear();
    m_exports.clear();
    m_sections.clear();

    // Open file in binary mode
    std::ifstream file(filepath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "[!] Failed to open file: " << filepath << std::endl;
        return false;
    }

    // Get file size and read entire file
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    m_file_data.resize(static_cast<size_t>(size));
    if (!file.read(reinterpret_cast<char*>(m_file_data.data()), size)) {
        std::cerr << "[!] Failed to read file: " << filepath << std::endl;
        return false;
    }

    std::cout << "[*] Loaded " << size << " bytes from " << filepath << std::endl;

    // Parse the PE structure
    if (!parse_headers()) {
        return false;
    }

    if (!parse_sections()) {
        return false;
    }

    if (!parse_exports()) {
        return false;
    }

    m_loaded = true;
    return true;
}

bool PEParser::parse_headers() {
    if (m_file_data.size() < sizeof(pe::DOS_HEADER)) {
        std::cerr << "[!] File too small for DOS header" << std::endl;
        return false;
    }

    // Parse DOS header
    m_dos_header = reinterpret_cast<const pe::DOS_HEADER*>(m_file_data.data());
    
    if (m_dos_header->e_magic != pe::DOS_MAGIC) {
        std::cerr << "[!] Invalid DOS signature (expected MZ)" << std::endl;
        return false;
    }

    // Validate PE header offset
    if (m_dos_header->e_lfanew < 0 || 
        static_cast<size_t>(m_dos_header->e_lfanew) + sizeof(pe::NT_HEADERS_64) > m_file_data.size()) {
        std::cerr << "[!] Invalid PE header offset" << std::endl;
        return false;
    }

    // Parse NT headers
    m_nt_headers = reinterpret_cast<const pe::NT_HEADERS_64*>(
        m_file_data.data() + m_dos_header->e_lfanew);

    if (m_nt_headers->Signature != pe::NT_SIGNATURE) {
        std::cerr << "[!] Invalid PE signature" << std::endl;
        return false;
    }

    // Check if 64-bit
    if (m_nt_headers->OptionalHeader.Magic != pe::OPTIONAL_HDR64_MAGIC) {
        std::cerr << "[!] Not a 64-bit PE file (PE32+ required)" << std::endl;
        return false;
    }
    m_is64bit = true;

    // Verify machine type
    if (m_nt_headers->FileHeader.Machine != pe::MACHINE_AMD64) {
        std::cerr << "[!] Not an AMD64 binary" << std::endl;
        return false;
    }

    std::cout << "[*] Valid PE64 file detected" << std::endl;
    std::cout << "[*] Number of sections: " << m_nt_headers->FileHeader.NumberOfSections << std::endl;

    return true;
}

bool PEParser::parse_sections() {
    // Calculate section headers location
    size_t section_offset = m_dos_header->e_lfanew + 
                           sizeof(uint32_t) +  // Signature
                           sizeof(pe::FILE_HEADER) + 
                           m_nt_headers->FileHeader.SizeOfOptionalHeader;

    uint16_t num_sections = m_nt_headers->FileHeader.NumberOfSections;

    for (uint16_t i = 0; i < num_sections; i++) {
        size_t offset = section_offset + (i * sizeof(pe::SECTION_HEADER));
        if (offset + sizeof(pe::SECTION_HEADER) > m_file_data.size()) {
            std::cerr << "[!] Section header out of bounds" << std::endl;
            return false;
        }

        const pe::SECTION_HEADER* section = 
            reinterpret_cast<const pe::SECTION_HEADER*>(m_file_data.data() + offset);
        m_sections.push_back(section);
    }

    return true;
}

uint32_t PEParser::rva_to_file_offset(uint32_t rva) const {
    // Find the section containing this RVA
    for (const auto* section : m_sections) {
        uint32_t section_start = section->VirtualAddress;
        uint32_t section_end = section_start + section->VirtualSize;

        if (rva >= section_start && rva < section_end) {
            // Calculate offset within section
            uint32_t offset_in_section = rva - section_start;
            return section->PointerToRawData + offset_in_section;
        }
    }

    // RVA not found in any section, might be in headers
    return rva;
}

bool PEParser::parse_exports() {
    // Get export directory from data directories
    const auto& export_dir_entry = m_nt_headers->OptionalHeader.DataDirectory[pe::DIRECTORY_ENTRY_EXPORT];
    
    if (export_dir_entry.VirtualAddress == 0 || export_dir_entry.Size == 0) {
        std::cerr << "[!] No export directory found" << std::endl;
        return false;
    }

    m_export_dir_rva = export_dir_entry.VirtualAddress;
    uint32_t export_dir_offset = rva_to_file_offset(m_export_dir_rva);

    if (export_dir_offset + sizeof(pe::EXPORT_DIRECTORY) > m_file_data.size()) {
        std::cerr << "[!] Export directory out of bounds" << std::endl;
        return false;
    }

    m_export_dir = reinterpret_cast<const pe::EXPORT_DIRECTORY*>(
        m_file_data.data() + export_dir_offset);

    // Get DLL name
    uint32_t name_offset = rva_to_file_offset(m_export_dir->Name);
    if (name_offset < m_file_data.size()) {
        m_dll_name = reinterpret_cast<const char*>(m_file_data.data() + name_offset);
    }

    std::cout << "[*] DLL Name: " << m_dll_name << std::endl;
    std::cout << "[*] Number of exported functions: " << m_export_dir->NumberOfFunctions << std::endl;
    std::cout << "[*] Number of named exports: " << m_export_dir->NumberOfNames << std::endl;

    // Parse export address table
    uint32_t func_table_offset = rva_to_file_offset(m_export_dir->AddressOfFunctions);
    uint32_t name_table_offset = rva_to_file_offset(m_export_dir->AddressOfNames);
    uint32_t ordinal_table_offset = rva_to_file_offset(m_export_dir->AddressOfNameOrdinals);

    const uint32_t* func_table = reinterpret_cast<const uint32_t*>(
        m_file_data.data() + func_table_offset);
    const uint32_t* name_table = reinterpret_cast<const uint32_t*>(
        m_file_data.data() + name_table_offset);
    const uint16_t* ordinal_table = reinterpret_cast<const uint16_t*>(
        m_file_data.data() + ordinal_table_offset);

    // Iterate through named exports
    for (uint32_t i = 0; i < m_export_dir->NumberOfNames; i++) {
        uint32_t name_rva = name_table[i];
        uint32_t name_file_offset = rva_to_file_offset(name_rva);
        
        if (name_file_offset >= m_file_data.size()) {
            continue;
        }

        const char* func_name = reinterpret_cast<const char*>(
            m_file_data.data() + name_file_offset);

        uint16_t ordinal_index = ordinal_table[i];
        uint32_t func_rva = func_table[ordinal_index];
        uint32_t func_file_offset = rva_to_file_offset(func_rva);

        ExportedFunction exp;
        exp.name = func_name;
        exp.ordinal = m_export_dir->Base + ordinal_index;
        exp.rva = func_rva;
        exp.file_offset = func_file_offset;

        m_exports.push_back(exp);
    }

    std::cout << "[*] Parsed " << m_exports.size() << " named exports" << std::endl;

    return true;
}

const uint8_t* PEParser::get_data_at_offset(uint32_t offset) const {
    if (offset >= m_file_data.size()) {
        return nullptr;
    }
    return m_file_data.data() + offset;
}

} // namespace syscall_detector
