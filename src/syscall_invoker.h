#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

namespace syscall_detector {

// Syscall Invoker - allows direct syscall invocation
// This class provides methods to invoke syscalls directly without going through ntdll
class SyscallInvoker {
public:
    SyscallInvoker();
    ~SyscallInvoker();

    // Initialize the invoker with a syscall table
    void set_syscall_table(const std::unordered_map<std::string, uint32_t>& table);

    // Get syscall number by name
    bool get_syscall_number(const std::string& name, uint32_t& number) const;

    // Invoke a syscall with the given number and arguments
    // Up to 4 arguments supported (most common case)
    // Returns the NTSTATUS result
    uint64_t invoke(uint32_t syscall_number, 
                    uint64_t arg1 = 0, 
                    uint64_t arg2 = 0, 
                    uint64_t arg3 = 0, 
                    uint64_t arg4 = 0) const;

    // Invoke syscall by name
    uint64_t invoke_by_name(const std::string& name,
                            uint64_t arg1 = 0,
                            uint64_t arg2 = 0,
                            uint64_t arg3 = 0,
                            uint64_t arg4 = 0) const;

    // Check if the invoker is available (has syscall table loaded)
    bool is_available() const { return !m_syscall_table.empty(); }

    // Demo: Invoke NtQuerySystemInformation to get basic system info
    bool demo_query_system_info();

private:
    std::unordered_map<std::string, uint32_t> m_syscall_table;
};

// External assembly function for making the actual syscall
// Defined in syscall_stub.asm
extern "C" uint64_t do_syscall(uint32_t syscall_number,
                                uint64_t arg1,
                                uint64_t arg2,
                                uint64_t arg3,
                                uint64_t arg4);

} // namespace syscall_detector
