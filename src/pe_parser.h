#pragma once

#include "pe_structures.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>

namespace syscall_detector {

// Represents an exported function from the DLL
struct ExportedFunction {
    std::string name;
    uint32_t ordinal;
    uint32_t rva;           // Relative Virtual Address
    uint32_t file_offset;   // Offset in the file
};

// PE Parser class - reads and parses PE files from disk
class PEParser {
public:
    PEParser();
    ~PEParser();

    // Load and parse a PE file from disk
    bool load(const std::string& filepath);

    // Check if a valid PE file is loaded
    bool is_loaded() const { return m_loaded; }

    // Check if this is a 64-bit PE
    bool is_64bit() const { return m_is64bit; }

    // Get all exported functions
    const std::vector<ExportedFunction>& get_exports() const { return m_exports; }

    // Get raw file data at a specific offset
    const uint8_t* get_data_at_offset(uint32_t offset) const;

    // Get file size
    size_t get_file_size() const { return m_file_data.size(); }

    // Convert RVA to file offset
    uint32_t rva_to_file_offset(uint32_t rva) const;

    // Get the DLL name
    const std::string& get_dll_name() const { return m_dll_name; }

private:
    bool parse_headers();
    bool parse_sections();
    bool parse_exports();

    std::vector<uint8_t> m_file_data;
    std::string m_filepath;
    std::string m_dll_name;
    bool m_loaded;
    bool m_is64bit;

    // Parsed headers
    const pe::DOS_HEADER* m_dos_header;
    const pe::NT_HEADERS_64* m_nt_headers;
    std::vector<const pe::SECTION_HEADER*> m_sections;
    const pe::EXPORT_DIRECTORY* m_export_dir;
    uint32_t m_export_dir_rva;

    // Exported functions
    std::vector<ExportedFunction> m_exports;
};

} // namespace syscall_detector
