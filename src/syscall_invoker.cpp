#include "syscall_invoker.h"
#include <iostream>
#include <cstring>

namespace syscall_detector {

SyscallInvoker::SyscallInvoker() = default;
SyscallInvoker::~SyscallInvoker() = default;

void SyscallInvoker::set_syscall_table(const std::unordered_map<std::string, uint32_t>& table) {
    m_syscall_table = table;
}

bool SyscallInvoker::get_syscall_number(const std::string& name, uint32_t& number) const {
    auto it = m_syscall_table.find(name);
    if (it != m_syscall_table.end()) {
        number = it->second;
        return true;
    }
    return false;
}

uint64_t SyscallInvoker::invoke(uint32_t syscall_number,
                                 uint64_t arg1,
                                 uint64_t arg2,
                                 uint64_t arg3,
                                 uint64_t arg4) const {
    // Call the assembly stub to perform the syscall
    return do_syscall(syscall_number, arg1, arg2, arg3, arg4);
}

uint64_t SyscallInvoker::invoke_by_name(const std::string& name,
                                         uint64_t arg1,
                                         uint64_t arg2,
                                         uint64_t arg3,
                                         uint64_t arg4) const {
    uint32_t syscall_number;
    if (!get_syscall_number(name, syscall_number)) {
        std::cerr << "[!] Syscall not found: " << name << std::endl;
        return 0xC0000001;  // STATUS_UNSUCCESSFUL
    }

    std::cout << "[*] Invoking " << name << " (syscall #" << syscall_number << ")" << std::endl;
    return invoke(syscall_number, arg1, arg2, arg3, arg4);
}

bool SyscallInvoker::demo_query_system_info() {
    // Demo: Query basic system information using NtQuerySystemInformation
    // SystemBasicInformation = 0
    
    uint32_t syscall_number;
    if (!get_syscall_number("NtQuerySystemInformation", syscall_number)) {
        std::cerr << "[!] NtQuerySystemInformation syscall not found" << std::endl;
        return false;
    }

    // SYSTEM_BASIC_INFORMATION structure (simplified)
    struct SYSTEM_BASIC_INFORMATION {
        uint32_t Reserved;
        uint32_t TimerResolution;
        uint32_t PageSize;
        uint32_t NumberOfPhysicalPages;
        uint32_t LowestPhysicalPageNumber;
        uint32_t HighestPhysicalPageNumber;
        uint32_t AllocationGranularity;
        uint64_t MinimumUserModeAddress;
        uint64_t MaximumUserModeAddress;
        uint64_t ActiveProcessorsAffinityMask;
        uint8_t  NumberOfProcessors;
    };

    SYSTEM_BASIC_INFORMATION sbi;
    memset(&sbi, 0, sizeof(sbi));
    uint32_t return_length = 0;

    std::cout << "[*] Calling NtQuerySystemInformation (syscall #" << syscall_number << ")..." << std::endl;

    // NtQuerySystemInformation(SystemBasicInformation = 0, &sbi, sizeof(sbi), &return_length)
    uint64_t status = invoke(syscall_number,
                             0,                              // SystemBasicInformation
                             reinterpret_cast<uint64_t>(&sbi),
                             sizeof(sbi),
                             reinterpret_cast<uint64_t>(&return_length));

    if (status == 0) {  // STATUS_SUCCESS
        std::cout << "[+] NtQuerySystemInformation succeeded!" << std::endl;
        std::cout << "    Page Size: " << sbi.PageSize << " bytes" << std::endl;
        std::cout << "    Number of Processors: " << static_cast<int>(sbi.NumberOfProcessors) << std::endl;
        std::cout << "    Allocation Granularity: " << sbi.AllocationGranularity << std::endl;
        return true;
    } else {
        std::cout << "[!] NtQuerySystemInformation failed with status: 0x" 
                  << std::hex << status << std::dec << std::endl;
        return false;
    }
}

} // namespace syscall_detector
