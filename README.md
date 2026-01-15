# DirectSyscall

A C++ tool for detecting and invoking Windows syscalls directly from `ntdll.dll` without using the Windows API.

## Features

- **Direct PE Parsing**: Reads `ntdll.dll` from disk, bypassing any userland API hooks
- **Syscall Detection**: Identifies x64 syscall stubs and extracts syscall numbers
- **Syscall Invocation**: Execute syscalls directly without going through `ntdll.dll`
- **Interactive CLI**: Search, list, and invoke syscalls interactively
- **No Windows.h**: PE structures defined manually to avoid Windows API dependencies

## How It Works

### Syscall Detection

The tool parses the PE (Portable Executable) format of `ntdll.dll`:

1. Reads the file from disk (not via `LoadLibrary`)
2. Parses DOS and NT headers
3. Locates the export directory
4. For each `Nt*` or `Zw*` function, examines the code bytes

x64 syscall stubs follow this pattern:
```asm
4C 8B D1       ; mov r10, rcx
B8 XX XX 00 00 ; mov eax, syscall_number
0F 05          ; syscall
C3             ; ret
```

The syscall number is extracted from the `mov eax` instruction at offset +4.

### Syscall Invocation

Once syscall numbers are known, they can be invoked directly using a small assembly stub:

```asm
mov r10, rcx        ; Windows syscall convention
mov eax, ecx        ; syscall number
mov rcx, rdx        ; shift arguments
mov rdx, r8
mov r8, r9
mov r9, [rsp+28h]
syscall             ; execute syscall
ret
```

This bypasses any hooks placed on `ntdll.dll` functions in memory.

## Building

### Requirements

- Windows 10/11 (x64)
- Visual Studio 2019+ with C++ and MASM support
- CMake 3.16+

### Build Steps

```powershell
# Create build directory
mkdir build
cd build

# Configure (for Visual Studio)
cmake .. -G "Visual Studio 17 2022" -A x64

# Build
cmake --build . --config Release

# Or open the .sln file in Visual Studio
```

The executable will be in `build/bin/Release/DirectSyscall.exe`.

## Usage

```powershell
# Run with default ntdll.dll path
.\DirectSyscall.exe

# Or specify a custom path
.\DirectSyscall.exe "C:\Windows\System32\ntdll.dll"
```

### Interactive Commands

| Command | Description |
|---------|-------------|
| `list` | List all detected syscalls |
| `search <pattern>` | Search for syscalls by name |
| `info <name>` | Show detailed info about a syscall |
| `demo` | Run a demo syscall (NtQuerySystemInformation) |
| `invoke <name>` | Invoke a syscall with no arguments |
| `help` | Show help message |
| `exit` | Exit the program |

### Example Session

```
syscall> search CreateFile
Search results for 'CreateFile':
  NtCreateFile -> 0x55 (85)
Found 1 matching syscall(s)

syscall> info NtCreateFile
Syscall Information:
-------------------------------------------
  Name:          NtCreateFile
  Syscall #:     85 (0x55)
  File Offset:   0x1a2b0
-------------------------------------------

syscall> demo
[*] Running demo: NtQuerySystemInformation
[*] Calling NtQuerySystemInformation (syscall #54)...
[+] NtQuerySystemInformation succeeded!
    Page Size: 4096 bytes
    Number of Processors: 8
    Allocation Granularity: 65536
```

## Project Structure

```
direct/
├── include/
│   └── pe_structures.h     # PE format structure definitions
├── src/
│   ├── main.cpp            # Entry point and CLI
│   ├── pe_parser.h/cpp     # PE file parsing
│   ├── syscall_extractor.h/cpp  # Syscall detection
│   ├── syscall_invoker.h/cpp    # Syscall invocation
│   └── syscall_stub.asm    # x64 assembly stub
├── CMakeLists.txt          # Build configuration
└── README.md               # This file
```

## Security Considerations

This tool demonstrates techniques used in:
- Security research
- EDR/AV bypass research
- Malware analysis
- Red team operations

**WARNING**: Invoking syscalls with incorrect arguments can crash your system. Use responsibly.

## Syscall Number Variability

Syscall numbers change between Windows versions. This tool reads them dynamically from the current system's `ntdll.dll`, ensuring compatibility across Windows versions.

## License

MIT License - Use at your own risk.
