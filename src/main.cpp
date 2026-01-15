#include "pe_parser.h"
#include "syscall_extractor.h"
#include "syscall_invoker.h"
#include <iostream>
#include <string>
#include <algorithm>
#include <cctype>

using namespace syscall_detector;

void print_banner() {
    std::cout << R"(
  ____  _               _     ____                      _ _ 
 |  _ \(_)_ __ ___  ___| |_  / ___| _   _ ___  ___ __ _| | |
 | | | | | '__/ _ \/ __| __| \___ \| | | / __|/ __/ _` | | |
 | |_| | | | |  __/ (__| |_   ___) | |_| \__ \ (_| (_| | | |
 |____/|_|_|  \___|\___|\__| |____/ \__, |___/\___\__,_|_|_|
                                    |___/                   
    Direct Syscall Detection & Invocation Tool (x64)
    ================================================
)" << std::endl;
}

void print_help() {
    std::cout << "\nCommands:" << std::endl;
    std::cout << "  list              - List all detected syscalls" << std::endl;
    std::cout << "  search <pattern>  - Search for syscalls by name" << std::endl;
    std::cout << "  info <name>       - Show detailed info about a syscall" << std::endl;
    std::cout << "  demo              - Run a demo syscall (NtQuerySystemInformation)" << std::endl;
    std::cout << "  invoke <name>     - Invoke a syscall (with no arguments)" << std::endl;
    std::cout << "  help              - Show this help message" << std::endl;
    std::cout << "  exit              - Exit the program" << std::endl;
    std::cout << std::endl;
}

std::string to_lower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return result;
}

void search_syscalls(const SyscallExtractor& extractor, const std::string& pattern) {
    std::string lower_pattern = to_lower(pattern);
    const auto& syscalls = extractor.get_syscalls();
    
    std::cout << "\nSearch results for '" << pattern << "':" << std::endl;
    std::cout << "-------------------------------------------" << std::endl;
    
    int count = 0;
    for (const auto& entry : syscalls) {
        if (to_lower(entry.name).find(lower_pattern) != std::string::npos) {
            std::cout << "  " << entry.name << " -> 0x" << std::hex << entry.syscall_number 
                      << std::dec << " (" << entry.syscall_number << ")" << std::endl;
            count++;
        }
    }
    
    if (count == 0) {
        std::cout << "  No syscalls found matching '" << pattern << "'" << std::endl;
    } else {
        std::cout << "\nFound " << count << " matching syscall(s)" << std::endl;
    }
}

void show_syscall_info(const SyscallExtractor& extractor, const std::string& name) {
    const SyscallEntry* entry = extractor.get_syscall_by_name(name);
    
    if (!entry) {
        // Try with Nt prefix
        std::string nt_name = "Nt" + name;
        entry = extractor.get_syscall_by_name(nt_name);
    }
    
    if (!entry) {
        // Try with Zw prefix
        std::string zw_name = "Zw" + name;
        entry = extractor.get_syscall_by_name(zw_name);
    }
    
    if (!entry) {
        std::cout << "[!] Syscall not found: " << name << std::endl;
        return;
    }
    
    std::cout << "\nSyscall Information:" << std::endl;
    std::cout << "-------------------------------------------" << std::endl;
    std::cout << "  Name:          " << entry->name << std::endl;
    std::cout << "  Syscall #:     " << entry->syscall_number 
              << " (0x" << std::hex << entry->syscall_number << std::dec << ")" << std::endl;
    std::cout << "  File Offset:   0x" << std::hex << entry->file_offset << std::dec << std::endl;
    std::cout << "-------------------------------------------" << std::endl;
}

void invoke_syscall(const SyscallInvoker& invoker, const std::string& name) {
    std::string syscall_name = name;
    
    // Add Nt prefix if not present
    if (name.substr(0, 2) != "Nt" && name.substr(0, 2) != "Zw") {
        syscall_name = "Nt" + name;
    }
    
    uint32_t syscall_number;
    if (!invoker.get_syscall_number(syscall_name, syscall_number)) {
        // Try Zw prefix
        syscall_name = "Zw" + name;
        if (!invoker.get_syscall_number(syscall_name, syscall_number)) {
            std::cout << "[!] Syscall not found: " << name << std::endl;
            return;
        }
    }
    
    std::cout << "[*] Invoking " << syscall_name << " (syscall #" << syscall_number << ")..." << std::endl;
    std::cout << "[!] WARNING: Invoking syscalls with no/wrong arguments may cause issues!" << std::endl;
    std::cout << "[*] Calling with all zero arguments..." << std::endl;
    
    uint64_t result = invoker.invoke(syscall_number, 0, 0, 0, 0);
    std::cout << "[*] Result: 0x" << std::hex << result << std::dec << std::endl;
    
    if (result == 0) {
        std::cout << "[+] STATUS_SUCCESS" << std::endl;
    } else {
        std::cout << "[!] Non-zero status returned (may indicate error or expected behavior)" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    print_banner();
    
    // Default ntdll path
    std::string ntdll_path = "C:\\Windows\\System32\\ntdll.dll";
    
    // Allow override via command line
    if (argc > 1) {
        ntdll_path = argv[1];
    }
    
    std::cout << "[*] Loading ntdll.dll from: " << ntdll_path << std::endl;
    
    // Parse the PE file
    PEParser parser;
    if (!parser.load(ntdll_path)) {
        std::cerr << "[!] Failed to load ntdll.dll" << std::endl;
        std::cerr << "[!] Make sure you're running on Windows and the path is correct." << std::endl;
        return 1;
    }
    
    // Extract syscalls
    SyscallExtractor extractor;
    if (!extractor.extract(parser)) {
        std::cerr << "[!] Failed to extract syscalls" << std::endl;
        return 1;
    }
    
    // Initialize syscall invoker
    SyscallInvoker invoker;
    invoker.set_syscall_table(extractor.get_syscall_map());
    
    // Print initial syscall table
    extractor.print_syscalls();
    
    // Interactive mode
    print_help();
    
    std::string line;
    while (true) {
        std::cout << "\nsyscall> ";
        if (!std::getline(std::cin, line)) {
            break;
        }
        
        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);
        
        if (line.empty()) {
            continue;
        }
        
        // Parse command
        std::string cmd, arg;
        size_t space_pos = line.find(' ');
        if (space_pos != std::string::npos) {
            cmd = line.substr(0, space_pos);
            arg = line.substr(space_pos + 1);
            // Trim arg
            arg.erase(0, arg.find_first_not_of(" \t"));
        } else {
            cmd = line;
        }
        
        cmd = to_lower(cmd);
        
        if (cmd == "exit" || cmd == "quit" || cmd == "q") {
            std::cout << "[*] Goodbye!" << std::endl;
            break;
        } else if (cmd == "list" || cmd == "ls") {
            extractor.print_syscalls();
        } else if (cmd == "search" || cmd == "find") {
            if (arg.empty()) {
                std::cout << "[!] Usage: search <pattern>" << std::endl;
            } else {
                search_syscalls(extractor, arg);
            }
        } else if (cmd == "info") {
            if (arg.empty()) {
                std::cout << "[!] Usage: info <syscall_name>" << std::endl;
            } else {
                show_syscall_info(extractor, arg);
            }
        } else if (cmd == "demo") {
            std::cout << "\n[*] Running demo: NtQuerySystemInformation" << std::endl;
            invoker.demo_query_system_info();
        } else if (cmd == "invoke" || cmd == "call") {
            if (arg.empty()) {
                std::cout << "[!] Usage: invoke <syscall_name>" << std::endl;
            } else {
                invoke_syscall(invoker, arg);
            }
        } else if (cmd == "help" || cmd == "?") {
            print_help();
        } else {
            std::cout << "[!] Unknown command: " << cmd << std::endl;
            std::cout << "[!] Type 'help' for available commands" << std::endl;
        }
    }
    
    return 0;
}
