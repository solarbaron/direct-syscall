#pragma once

#include "pe_parser.h"
#include <string>
#include <vector>
#include <unordered_map>

namespace syscall_detector {

// Represents a detected syscall
struct SyscallEntry {
    std::string name;           // Function name (e.g., "NtCreateFile")
    uint32_t syscall_number;    // The syscall number
    uint32_t file_offset;       // Offset in the file where the syscall stub is
    bool is_valid;              // Whether this entry represents a valid syscall
};

// Syscall Extractor - identifies and extracts syscall numbers from PE exports
class SyscallExtractor {
public:
    SyscallExtractor();
    ~SyscallExtractor();

    // Extract syscalls from a loaded PE file
    bool extract(const PEParser& parser);

    // Get all detected syscalls
    const std::vector<SyscallEntry>& get_syscalls() const { return m_syscalls; }

    // Get syscall by name
    const SyscallEntry* get_syscall_by_name(const std::string& name) const;

    // Get syscall by number
    const SyscallEntry* get_syscall_by_number(uint32_t number) const;

    // Get a map of syscall name -> number for quick lookup
    const std::unordered_map<std::string, uint32_t>& get_syscall_map() const { return m_syscall_map; }

    // Print all detected syscalls
    void print_syscalls() const;

private:
    // Check if a function name looks like a syscall (Nt* or Zw*)
    bool is_syscall_name(const std::string& name) const;

    // Extract syscall number from function bytes
    bool extract_syscall_number(const uint8_t* func_bytes, size_t max_size, uint32_t& syscall_num) const;

    std::vector<SyscallEntry> m_syscalls;
    std::unordered_map<std::string, uint32_t> m_syscall_map;
    std::unordered_map<uint32_t, std::string> m_number_to_name;
};

} // namespace syscall_detector
