cmake_minimum_required(VERSION 3.16)
project(DirectSyscall VERSION 1.0.0 LANGUAGES CXX ASM_MASM)

# Require Windows and x64
if(NOT WIN32)
    message(FATAL_ERROR "This project only supports Windows")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "This project only supports 64-bit builds (x64)")
endif()

# C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable ASM_MASM for assembly files
enable_language(ASM_MASM)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)

# Source files
set(SOURCES
    src/main.cpp
    src/pe_parser.cpp
    src/syscall_extractor.cpp
    src/syscall_invoker.cpp
)

# Assembly files (MASM)
set(ASM_SOURCES
    src/syscall_stub.asm
)

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES} ${ASM_SOURCES})

# Set MASM flags for x64
set_source_files_properties(${ASM_SOURCES} PROPERTIES
    COMPILE_FLAGS "/c"
)

# Compiler flags for MSVC
if(MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE
        /W4             # High warning level
        /WX-            # Don't treat warnings as errors (for development)
        /permissive-    # Strict conformance
        /Zc:__cplusplus # Report correct C++ version
    )
    
    # Disable specific warnings that are noisy but not critical
    target_compile_options(${PROJECT_NAME} PRIVATE
        /wd4100         # Unreferenced formal parameter
    )
endif()

# Output directory
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Installation
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)

# Print configuration info
message(STATUS "")
message(STATUS "DirectSyscall Configuration:")
message(STATUS "  Version:       ${PROJECT_VERSION}")
message(STATUS "  Platform:      Windows x64")
message(STATUS "  Generator:     ${CMAKE_GENERATOR}")
message(STATUS "  Build Type:    ${CMAKE_BUILD_TYPE}")
message(STATUS "")
