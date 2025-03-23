cmake_minimum_required(VERSION 3.30)
project(WinAPI_Hasher)

set(CMAKE_CXX_STANDARD 23)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

file(WRITE ${CMAKE_SOURCE_DIR}/.gitignore "build/\ncmake-build-*/\n.idea/\n.vs/\nhash.exe\n.clang-format")

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O1  /GL")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /OPT:REF /OPT:ICF")

add_executable(WinAPI_Hasher main.cpp)
target_link_libraries(WinAPI_Hasher dbghelp)


set_target_properties(WinAPI_Hasher PROPERTIES OUTPUT_NAME "hash")