#include "syscall_extractor.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <cstring>

namespace syscall_detector {

// x64 syscall stub patterns
// Standard pattern:
// 4C 8B D1       mov r10, rcx
// B8 XX XX 00 00 mov eax, syscall_number
// 0F 05          syscall
// C3             ret

// Alternative pattern (with test for Meltdown mitigation):
// 4C 8B D1       mov r10, rcx
// B8 XX XX 00 00 mov eax, syscall_number
// F6 04 25 08 03 FE 7F 01  test byte ptr [0x7FFE0308], 1
// 75 03          jne +3
// 0F 05          syscall
// C3             ret
// CD 2E          int 2Eh
// C3             ret

constexpr uint8_t PATTERN_MOV_R10_RCX[] = { 0x4C, 0x8B, 0xD1 };
constexpr uint8_t PATTERN_MOV_EAX_PREFIX = 0xB8;

SyscallExtractor::SyscallExtractor() = default;
SyscallExtractor::~SyscallExtractor() = default;

bool SyscallExtractor::is_syscall_name(const std::string& name) const {
    // Syscalls in ntdll start with "Nt" or "Zw"
    if (name.length() < 3) {
        return false;
    }
    
    // Check for Nt prefix
    if (name[0] == 'N' && name[1] == 't') {
        return true;
    }
    
    // Check for Zw prefix
    if (name[0] == 'Z' && name[1] == 'w') {
        return true;
    }
    
    return false;
}

bool SyscallExtractor::extract_syscall_number(const uint8_t* func_bytes, size_t max_size, uint32_t& syscall_num) const {
    if (max_size < 8) {
        return false;
    }

    // Check for x64 syscall stub pattern
    // First 3 bytes should be: mov r10, rcx (4C 8B D1)
    if (memcmp(func_bytes, PATTERN_MOV_R10_RCX, sizeof(PATTERN_MOV_R10_RCX)) != 0) {
        return false;
    }

    // Next byte should be: mov eax, imm32 (B8)
    if (func_bytes[3] != PATTERN_MOV_EAX_PREFIX) {
        return false;
    }

    // Extract the syscall number (little-endian 32-bit value at offset 4)
    syscall_num = *reinterpret_cast<const uint32_t*>(func_bytes + 4);

    // Validate: syscall numbers are typically in range 0-0x1000
    // Larger values likely indicate this isn't a real syscall stub
    if (syscall_num > 0x2000) {
        return false;
    }

    // Additional validation: check for syscall instruction (0F 05) or test pattern
    // Look for syscall instruction within reasonable distance
    bool found_syscall_inst = false;
    for (size_t i = 8; i < std::min(max_size, size_t(32)); i++) {
        if (func_bytes[i] == 0x0F && i + 1 < max_size && func_bytes[i + 1] == 0x05) {
            found_syscall_inst = true;
            break;
        }
        // Also check for int 2E (CD 2E) which is legacy syscall method
        if (func_bytes[i] == 0xCD && i + 1 < max_size && func_bytes[i + 1] == 0x2E) {
            found_syscall_inst = true;
            break;
        }
    }

    return found_syscall_inst;
}

bool SyscallExtractor::extract(const PEParser& parser) {
    m_syscalls.clear();
    m_syscall_map.clear();
    m_number_to_name.clear();

    if (!parser.is_loaded()) {
        std::cerr << "[!] PE file not loaded" << std::endl;
        return false;
    }

    if (!parser.is_64bit()) {
        std::cerr << "[!] Only 64-bit PE files are supported" << std::endl;
        return false;
    }

    const auto& exports = parser.get_exports();
    size_t file_size = parser.get_file_size();

    std::cout << "[*] Scanning " << exports.size() << " exports for syscalls..." << std::endl;

    for (const auto& exp : exports) {
        // Only check functions that look like syscalls
        if (!is_syscall_name(exp.name)) {
            continue;
        }

        // Get function bytes
        const uint8_t* func_bytes = parser.get_data_at_offset(exp.file_offset);
        if (!func_bytes) {
            continue;
        }

        // Calculate max available bytes
        size_t max_bytes = file_size - exp.file_offset;
        if (max_bytes > 64) {
            max_bytes = 64;  // Syscall stubs are small
        }

        // Try to extract syscall number
        uint32_t syscall_num;
        if (extract_syscall_number(func_bytes, max_bytes, syscall_num)) {
            SyscallEntry entry;
            entry.name = exp.name;
            entry.syscall_number = syscall_num;
            entry.file_offset = exp.file_offset;
            entry.is_valid = true;

            m_syscalls.push_back(entry);
            m_syscall_map[exp.name] = syscall_num;
            m_number_to_name[syscall_num] = exp.name;
        }
    }

    // Sort by syscall number
    std::sort(m_syscalls.begin(), m_syscalls.end(), 
              [](const SyscallEntry& a, const SyscallEntry& b) {
                  return a.syscall_number < b.syscall_number;
              });

    std::cout << "[*] Found " << m_syscalls.size() << " syscalls" << std::endl;

    return !m_syscalls.empty();
}

const SyscallEntry* SyscallExtractor::get_syscall_by_name(const std::string& name) const {
    for (const auto& entry : m_syscalls) {
        if (entry.name == name) {
            return &entry;
        }
    }
    return nullptr;
}

const SyscallEntry* SyscallExtractor::get_syscall_by_number(uint32_t number) const {
    for (const auto& entry : m_syscalls) {
        if (entry.syscall_number == number) {
            return &entry;
        }
    }
    return nullptr;
}

void SyscallExtractor::print_syscalls() const {
    std::cout << "\n";
    std::cout << "===========================================" << std::endl;
    std::cout << "           DETECTED SYSCALLS" << std::endl;
    std::cout << "===========================================" << std::endl;
    std::cout << std::left << std::setw(40) << "Name" 
              << std::right << std::setw(10) << "Number (Dec)"
              << std::setw(12) << "Number (Hex)" << std::endl;
    std::cout << "-------------------------------------------" << std::endl;

    for (const auto& entry : m_syscalls) {
        std::cout << std::left << std::setw(40) << entry.name
                  << std::right << std::setw(10) << entry.syscall_number
                  << std::setw(12) << std::hex << "0x" << entry.syscall_number 
                  << std::dec << std::endl;
    }

    std::cout << "===========================================" << std::endl;
    std::cout << "Total: " << m_syscalls.size() << " syscalls detected" << std::endl;
    std::cout << "===========================================" << std::endl;
}

} // namespace syscall_detector
