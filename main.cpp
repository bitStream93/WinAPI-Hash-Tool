/*
* Copyright (C) 2025 bitStream
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * As a special requirement, any source code distribution must include the
 * original license text and retain this notice.
 *
 * If you modify this Program, or any covered work, by linking or combining
 * it with other code, such other code is not for that reason alone subject
 * to any of the requirements of the GNU Affero GPL version 3.
 *
 * ADDITIONAL PERMISSION under the GNU Affero GPL version 3 section 7:
 * If you modify this Program, or any covered work, by linking or
 * combining it with [name of library, name of software, etc],
 * containing parts covered by the terms of [name of license],
 * the licensors of this Program grant you additional permission
 * to convey the resulting work.
 */

#include <windows.h>
#include <algorithm>
#include <array>
#include <cstdlib>
#include <dbghelp.h>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>
#pragma comment(lib, "dbghelp.lib")
enum ConsoleColor {
  BLACK = 0,
  DARK_BLUE = 1,
  DARK_GREEN = 2,
  DARK_CYAN = 3,
  DARK_RED = 4,
  DARK_MAGENTA = 5,
  DARK_YELLOW = 6,
  GRAY = 7,
  DARK_GRAY = 8,
  BLUE = 9,
  GREEN = 10,
  CYAN = 11,
  RED = 12,
  MAGENTA = 13,
  YELLOW = 14,
  WHITE = 15
};

void SetConsoleColor(const ConsoleColor foreground,
                     const ConsoleColor background = BLACK) {
  HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  SetConsoleTextAttribute(hConsole, (background << 4) | foreground);
}

void ResetConsoleColor() { SetConsoleColor(GRAY); }

struct ApiFunction {
  std::string name;
  std::string dll;
  uint32_t hash;
};

uint32_t CalculateDjb2Hash(const char *str) {
  if (!str)
    return 0;

  constexpr uint32_t INITIAL_HASH = 5381;
  uint32_t hash = INITIAL_HASH;

  while (unsigned char c = *str++) {
    if (hash > 0xffffffff / 33) {
      hash = INITIAL_HASH;
    }
    hash = ((hash << 5) + hash) + c;
  }
  return hash;
}

struct DllModule {
  HMODULE handle;

  DllModule(const std::string &path) {
    handle = LoadLibraryExA(path.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
  }

  ~DllModule() {
    if (handle)
      FreeLibrary(handle);
  }

  operator HMODULE() const { return handle; }
  operator bool() const { return handle != nullptr; }
};

std::string GetSystemDirectory() {
  std::unique_ptr<char, decltype(&free)> systemRoot(nullptr, free); {
    char *temp = nullptr;
    size_t len = 0;
    if (_dupenv_s(&temp, &len, "SystemRoot") != 0 || !temp) {
      SetConsoleColor(RED);
      std::cerr << "[!]\tError: SystemRoot environment variable not found\n";
      ResetConsoleColor();
      return "";
    }
    systemRoot.reset(temp);
  }

  const std::filesystem::path system_dir =
      std::filesystem::path(systemRoot.get()) / "System32";
  return system_dir.string();
}

std::vector<std::string> GetDefaultDlls() {
  std::vector<std::string> dlls;
  const std::string system_dir = GetSystemDirectory();

  if (system_dir.empty()) {
    return dlls;
  }

  constexpr std::array<const char *, 32> target_dlls = {
      "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll",
      "gdi32.dll", "advapi32.dll", "shell32.dll", "ole32.dll",
      "oleaut32.dll", "combase.dll", "comdlg32.dll", "ws2_32.dll",
      "wininet.dll", "urlmon.dll", "winhttp.dll", "secur32.dll",
      "crypt32.dll", "wintrust.dll", "bcrypt.dll", "ncrypt.dll",
      "uxtheme.dll", "dwmapi.dll", "d3d11.dll", "dxgi.dll",
      "winmm.dll", "avrt.dll", "shlwapi.dll", "psapi.dll",
      "setupapi.dll", "wtsapi32.dll", "iphlpapi.dll", "msvcrt.dll"};

  for (const auto &dll_name : target_dlls) {
    if (std::filesystem::path dll_path =
          std::filesystem::path(system_dir) / dll_name;
      std::filesystem::exists(dll_path)) {
      dlls.push_back(dll_path.string());
    }
  }
  return dlls;
}

std::string NormalizeDllName(const std::string &name) {
  std::string result = name;
  std::ranges::transform(result, result.begin(),
                         [](unsigned char c) { return std::tolower(c); });

  const std::string allowed = "abcdefghijklmnopqrstuvwxyz0123456789.-_";
  if (const auto pos = result.find_first_not_of(allowed);
    pos != std::string::npos) {
    SetConsoleColor(RED);
    std::cerr << "[!]\tError: Invalid character '" << result[pos]
        << "' in DLL name: " << name << "\n";
    ResetConsoleColor();
    return "";
  }

  if (result.length() < 4 || result.substr(result.length() - 4) != ".dll") {
    result += ".dll";
  }

  return result;
}

std::vector<std::string>
GetCustomDlls(const std::vector<std::string> &dll_names) {
  std::vector<std::string> dlls;
  const std::string system_dir = GetSystemDirectory();
  if (system_dir.empty()) {
    return dlls;
  }
  for (const auto &name : dll_names) {
    std::string dll_name = NormalizeDllName(name);
    if (dll_name.empty())
      continue;
    std::filesystem::path dll_path =
        std::filesystem::path(system_dir) / dll_name;
    bool found = false;
    if (std::filesystem::exists(dll_path)) {
      dlls.push_back(dll_path.string());
      found = true;
    } else {
      SetConsoleColor(YELLOW);
      std::cerr << "[!]\tWarning: " << dll_name << " not found in System32\n";
      ResetConsoleColor();

      if (std::filesystem::exists(dll_name)) {
        dlls.push_back(dll_name);
        found = true;
      }
    }
    if (!found) {
      SetConsoleColor(RED);
      std::cerr << "[!]\tCould not find DLL: " << dll_name << "\n";
      ResetConsoleColor();
    }
  }
  return dlls;
}

std::vector<std::string> GetExportsFromDll(const std::string &dll_path) {
  std::vector<std::string> exports;
  try {
    DllModule hModule(dll_path);
    if (!hModule) {
      DWORD error = GetLastError();
      SetConsoleColor(RED);
      std::cerr << "[!]\tError loading DLL " << dll_path << ": "
          << std::system_category().message(error)
          << " (Code: " << error << ")\n";
      ResetConsoleColor();
      return exports;
    }

    const PIMAGE_NT_HEADERS pNTHeader = ImageNtHeader(hModule);
    if (!pNTHeader) {
      SetConsoleColor(RED);
      std::cerr << "[!]\tInvalid PE header in " << dll_path << "\n";
      ResetConsoleColor();
      return exports;
    }

    if (pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        .Size == 0) {
      return exports;
    }

    const DWORD exportDirRVA =
        pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
        .VirtualAddress;

    const auto pExports = static_cast<PIMAGE_EXPORT_DIRECTORY>(
      ImageRvaToVa(pNTHeader, hModule, exportDirRVA, nullptr));
    if (!pExports) {
      SetConsoleColor(RED);
      std::cerr << "[!]\tFailed to access export directory in "
          << dll_path << "\n";
      ResetConsoleColor();
      return exports;
    }

    const auto pNames = static_cast<PDWORD>(
      ImageRvaToVa(pNTHeader, hModule, pExports->AddressOfNames, nullptr));
    if (!pNames) {
      SetConsoleColor(RED);
      std::cerr << "[!]\tFailed to access export names in "
          << dll_path << "\n";
      ResetConsoleColor();
      return exports;
    }

    exports.reserve(pExports->NumberOfNames);
    for (DWORD i = 0; i < pExports->NumberOfNames; i++) {
      auto pszName = static_cast<PSTR>(
        ImageRvaToVa(pNTHeader, hModule, pNames[i], nullptr));
      if (pszName && *pszName) {
        exports.emplace_back(pszName);
      }
    }
  } catch (const std::exception &e) {
    SetConsoleColor(RED);
    std::cerr << "[!]\tException while extracting exports from "
        << dll_path << ": " << e.what() << "\n";
    ResetConsoleColor();
  }
  return exports;
}

std::vector<ApiFunction>
CollectApiFunctions(const std::vector<std::string> &dlls,
                    bool verbose = false) {
  std::vector<ApiFunction> functions;
  const size_t total_dlls = dlls.size();
  size_t processed = 0;
  size_t total_functions = 0;

  const size_t max_name_length = 50;

  const auto hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
  CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
  GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
  std::ios state(nullptr);
  state.copyfmt(std::cout);
  for (const auto &dll : dlls) {
    processed++;
    std::string dll_name = std::filesystem::path(dll).filename().string();
    if (verbose) {
      SetConsoleColor(CYAN);
      std::cout << "\n[" << processed << "/" << total_dlls << "] ";
      SetConsoleColor(WHITE);
      std::cout << "Processing: ";
      SetConsoleColor(GREEN, BLACK);
      std::cout << dll_name;
      ResetConsoleColor();
      std::cout << "\n";
    }
    try {
      std::vector<std::string> exports = GetExportsFromDll(dll);
      if (verbose) {
        SetConsoleColor(CYAN);
        std::cout << "  | ";
        SetConsoleColor(YELLOW);
        std::cout << "Found " << exports.size() << " functions\n";
        ResetConsoleColor();
      }
      for (const auto &func : exports) {
        uint32_t hash = CalculateDjb2Hash(func.c_str());
        functions.push_back({func, dll_name, hash});
        total_functions++;
        if (verbose) {
          SetConsoleColor(CYAN);
          std::cout << "  | ";
          SetConsoleColor(WHITE);

          std::cout << std::setw(max_name_length) << std::left << func
              << " -> ";
          SetConsoleColor(MAGENTA);
          std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0')
              << hash;
          ResetConsoleColor();
          std::cout << "\n";

          std::cout.copyfmt(state);
        }
      }
    } catch (const std::exception &e) {
      if (verbose) {
        SetConsoleColor(RED);
        std::cerr << "  | Error processing " << dll << ": " << e.what() << "\n";
        ResetConsoleColor();
      }
    }
    if (verbose && processed < total_dlls) {
      SetConsoleColor(CYAN);
      std::cout << "  v\n";
      ResetConsoleColor();
    }
  }
  if (verbose) {
    SetConsoleColor(GREEN);
    std::cout << "\n[+]\tProcessed " << total_dlls << " DLLs and found "
        << total_functions << " functions\n\n";
    ResetConsoleColor();
  }
  return functions;
}

bool SaveToStructHeader(const std::vector<ApiFunction> &functions,
                        const std::string &filename) {
  std::ofstream file(filename);
  if (!file.is_open()) {
    SetConsoleColor(RED);
    std::cerr << "[!]\tFailed to create header file: " << filename << "\n";
    ResetConsoleColor();
    return false;
  }
  file << "#pragma once\n\n";
  file << "#include <cstdint>\n\n";
  file << "struct ApiHash {\n";
  file << "    const char* name;\n";
  file << "    const char* dll;\n";
  file << "    uint32_t hash;\n";
  file << "};\n\n";
  file << "constexpr ApiHash API_HASHES[] = {\n";

  std::ios state(nullptr);
  state.copyfmt(file);
  for (const auto &[name, dll, hash] : functions) {
    file << "    {\"" << name << "\", \"" << dll << "\", 0x" << std::hex << hash
        << "},\n";
    file.copyfmt(state);
  }
  file << "};\n";
  file.close();
  SetConsoleColor(GREEN);
  std::cout << "[+]\t";
  ResetConsoleColor();
  std::cout << "Saved C++ header to: ";
  SetConsoleColor(CYAN);
  std::cout << filename << "\n";
  ResetConsoleColor();
  return true;
}

bool SaveToDefineHeader(const std::vector<ApiFunction> &functions,
                        const std::string &filename) {
  std::ofstream file(filename);
  if (!file.is_open()) {
    SetConsoleColor(RED);
    std::cerr << "[!]\tFailed to create header file: " << filename << "\n";
    ResetConsoleColor();
    return false;
  }
  file << "#pragma once\n\n";
  file << "// Windows API Functions - djb2 Hash\n";
  file << "// Automatically generated - Do not modify\n\n";

  std::ios state(nullptr);
  state.copyfmt(file);
  for (const auto &func : functions) {
    std::string macro_name = func.name;
    for (char &c : macro_name) {
      if (!std::isalnum(c))
        c = '_';
    }

    file << "#define " << std::setw(30) << std::left << macro_name
        << " 0x" << std::hex << std::setw(8) << std::setfill('0') << func.hash
        << "\n";

    file.copyfmt(state);
  }

  file.close();
  SetConsoleColor(GREEN);
  std::cout << "[+]\t";
  ResetConsoleColor();
  std::cout << "Saved C header to: ";
  SetConsoleColor(CYAN);
  std::cout << filename << "\n";
  ResetConsoleColor();
  return true;
}

std::vector<std::string> SplitString(const std::string &str, char delimiter,
                                     bool removeEmpty = true) {
  std::vector<std::string> tokens;
  std::stringstream ss(str);
  std::string token;
  while (std::getline(ss, token, delimiter)) {
    if (!removeEmpty || !token.empty()) {
      tokens.push_back(token);
    }
  }
  return tokens;
}

void PrintTitle() {
  const int boxWidth = 59;
  std::string title = "Windows API Function Hasher";
  std::string github = "bitStream  ->   https://github.com/bitStream93";

  int titlePadding = (boxWidth - title.length()) / 2;
  int githubPadding = (boxWidth - github.length()) / 2;

  SetConsoleColor(GREEN);
  std::cout << "\n";
  std::cout <<
      "+-----------------------------------------------------------+\n";

  std::cout << "|";
  SetConsoleColor(WHITE);
  std::cout << std::string(titlePadding, ' ') << title << std::string(
      boxWidth - title.length() - titlePadding, ' ');
  SetConsoleColor(GREEN);
  std::cout << "|\n";

  std::cout << "|";
  SetConsoleColor(DARK_GRAY);
  std::cout << std::string(githubPadding, ' ') << github << std::string(
      boxWidth - github.length() - githubPadding, ' ');
  SetConsoleColor(GREEN);
  std::cout << "|\n";

  std::cout <<
      "+-----------------------------------------------------------+\n\n";

  ResetConsoleColor();
}

void PrintUsage(const char *program_name) {
  PrintTitle();

  std::string exe_name =
      std::filesystem::path(program_name).filename().string();
  SetConsoleColor(YELLOW);
  std::cout << "Usage: ";
  SetConsoleColor(WHITE);
  std::cout << exe_name << " [options]\n\n";
  SetConsoleColor(YELLOW);
  std::cout << "Options:\n";
  ResetConsoleColor();
  std::cout << "  ";
  SetConsoleColor(GREEN);
  std::cout << "-v";
  ResetConsoleColor();
  std::cout << "\t\t\t\t\t\tEnable verbose output\n";
  std::cout << "  ";
  SetConsoleColor(GREEN);
  std::cout << "-h <file>";
  ResetConsoleColor();
  std::cout << "\t\t\t\t\tGenerate C++ Style header file\n";
  std::cout << "  ";
  SetConsoleColor(GREEN);
  std::cout << "-c <file>";
  ResetConsoleColor();
  std::cout << "\t\t\t\t\tGenerate C Style header file\n";
  std::cout << "  ";
  SetConsoleColor(GREEN);
  std::cout << "--dll \"dll1,dll2\"";
  ResetConsoleColor();
  std::cout << "\t\t\t\tComma-separated list of DLLs to process\n";
  SetConsoleColor(DARK_GRAY);
  std::cout <<
      "\t\t\t\t\t\t\t;Use without -dll to process default system DLLs\n";
  std::cout << "  ";
  SetConsoleColor(GREEN);
  std::cout << "--func <dll>:<function1,function2,...>";
  ResetConsoleColor();
  std::cout << "\tHash specific functions from a DLL\n";
  std::cout << "  ";
  SetConsoleColor(GREEN);
  std::cout << "--help";
  ResetConsoleColor();
  std::cout << "\t\t\t\t\tShow Help\n\n";
  SetConsoleColor(YELLOW);
  std::cout << "Examples:\n";
  ResetConsoleColor();
  std::cout << "  ";
  SetConsoleColor(WHITE);
  std::cout << exe_name << " -v";
  ResetConsoleColor();
  std::cout << "\t\t\t\t\t\t# Process default DLLs with verbose output\n";
  std::cout << "  ";
  SetConsoleColor(WHITE);
  std::cout << exe_name << " --dll \"kernel32,user32\"";
  ResetConsoleColor();
  std::cout << "\t\t\t# Process specific DLLs\n";
  std::cout << "  ";
  SetConsoleColor(WHITE);
  std::cout << exe_name << " -c api_hashes.h";
  ResetConsoleColor();
  std::cout << "\t\t\t\t# Generate C style header\n";
  std::cout << "  ";
  SetConsoleColor(WHITE);
  std::cout << exe_name << " --func kernel32:CreateFileA,ReadFile";
  ResetConsoleColor();
  std::cout << "\t\t# Hash specific functions\n\n";
}

bool HashSpecificFunctions(const std::string &dll_func_spec) {
  std::ios state(nullptr);
  state.copyfmt(std::cout);
  size_t delimiter_pos = dll_func_spec.find(':');
  if (delimiter_pos == std::string::npos) {
    SetConsoleColor(RED);
    std::cerr << "[!]\tError: Invalid format for --func option. Use "
        "<dll>:<function1,function2,...>\n";
    ResetConsoleColor();
    return false;
  }

  std::string dll_name = dll_func_spec.substr(0, delimiter_pos);
  std::string func_names_str = dll_func_spec.substr(delimiter_pos + 1);
  std::vector<std::string> func_names = SplitString(func_names_str, ',');

  if (func_names.empty()) {
    SetConsoleColor(RED);
    std::cerr << "[!]\tError: No functions specified\n";
    ResetConsoleColor();
    return false;
  }

  dll_name = NormalizeDllName(dll_name);
  if (dll_name.empty()) {
    return false;
  }

  const std::string system_dir = GetSystemDirectory();
  if (system_dir.empty()) {
    return false;
  }

  std::filesystem::path dll_path = std::filesystem::path(system_dir) / dll_name;
  bool found = false;

  if (std::filesystem::exists(dll_path)) {
    found = true;
  } else if (std::filesystem::exists(dll_name)) {
    dll_path = dll_name;
    found = true;
  }

  if (!found) {
    SetConsoleColor(RED);
    std::cerr << "[!]\tError: DLL not found: " << dll_name << "\n";
    ResetConsoleColor();
    return false;
  }

  std::vector<std::string> exports = GetExportsFromDll(dll_path.string());
  bool any_function_found = false;

  for (const auto &func_name : func_names) {
    auto it = std::find(exports.begin(), exports.end(), func_name);
    if (it == exports.end()) {
      SetConsoleColor(RED);
      std::cerr << "[!]\tError: Function '" << func_name << "' not found in "
          << dll_name << "\n";
      ResetConsoleColor();
      continue;
    }

    uint32_t hash = CalculateDjb2Hash(func_name.c_str());
    SetConsoleColor(GREEN);
    std::cout << "[+]\t";
    ResetConsoleColor();
    std::cout << "Function: ";
    SetConsoleColor(WHITE);
    std::cout << func_name;
    ResetConsoleColor();
    std::cout << "\n      \tIn DLL:   ";
    SetConsoleColor(WHITE);
    std::cout << dll_name;
    ResetConsoleColor();
    std::cout << "\n      \tHash:     ";
    SetConsoleColor(MAGENTA);
    std::cout << "0x" << std::hex << std::setw(8) << std::setfill('0') << hash;
    ResetConsoleColor();
    std::cout << "\n\n";

    any_function_found = true;
  }

  std::cout.copyfmt(state);
  return any_function_found;
}

int main(int argc, char *argv[]) {
  bool verbose = false;
  std::string struct_header_file;
  std::string define_header_file;
  std::vector<std::string> custom_dlls;
  std::string specific_function;
  bool valid_args = true;
  std::string error_message;
  system("cls");
  if (argc < 2) {
    PrintUsage(argv[0]);
    return 0;
  }

  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "-v") {
      verbose = true;
    } else if (arg == "-h") {
      if (i + 1 < argc) {
        struct_header_file = argv[++i];
      } else {
        valid_args = false;
        error_message = "Missing filename after -h option";
        break;
      }
    } else if (arg == "-c") {
      if (i + 1 < argc) {
        define_header_file = argv[++i];
      } else {
        valid_args = false;
        error_message = "Missing filename after -c option";
        break;
      }
    } else if (arg == "--dll") {
      if (i + 1 < argc) {
        custom_dlls = SplitString(argv[++i], ',', false);
      } else {
        valid_args = false;
        error_message = "Missing DLL list after --dll option";
        break;
      }
    } else if (arg == "--func") {
      if (i + 1 < argc) {
        specific_function = argv[++i];
        if (specific_function.find(':') == std::string::npos) {
          valid_args = false;
          error_message =
              "Invalid format for --func. Use <dll>:<function1,function2,...>";
          break;
        }
      } else {
        valid_args = false;
        error_message = "Missing function specification after --func option";
        break;
      }
    } else if (arg == "--help") {
      PrintUsage(argv[0]);
      return 0;
    } else {
      valid_args = false;
      error_message = "Unknown option: " + arg;
      break;
    }
  }

  if (!valid_args) {
    SetConsoleColor(RED);
    std::cerr << "[!]\tError: " << error_message << "\n";
    ResetConsoleColor();
    PrintUsage(argv[0]);
    return 1;
  }

  PrintTitle();

  if (!specific_function.empty()) {
    return HashSpecificFunctions(specific_function) ? 0 : 1;
  }

  std::vector<std::string> dll_paths;
  if (custom_dlls.empty()) {
    SetConsoleColor(CYAN);
    std::cout << "[+]\t";
    ResetConsoleColor();
    std::cout <<
        "Retrieving Windows API functions from default system DLLs...\n";
    dll_paths = GetDefaultDlls();
  } else {
    SetConsoleColor(CYAN);
    std::cout << "[+]\t";
    ResetConsoleColor();
    std::cout << "Retrieving Windows API functions from specified DLLs: ";
    SetConsoleColor(GREEN);
    for (size_t i = 0; i < custom_dlls.size(); i++) {
      if (custom_dlls[i].empty())
        continue;
      std::cout << custom_dlls[i];
      if (i < custom_dlls.size() - 1)
        std::cout << ", ";
    }
    ResetConsoleColor();
    std::cout << "\n";
    dll_paths = GetCustomDlls(custom_dlls);
  }

  if (dll_paths.empty()) {
    SetConsoleColor(RED);
    std::cerr << "[!]No valid DLLs found to process\n";
    ResetConsoleColor();
    return 1;
  }

  const auto functions = CollectApiFunctions(dll_paths, verbose);

  SetConsoleColor(GREEN);
  std::cout << "[+]\t";
  ResetConsoleColor();
  std::cout << "Found ";
  SetConsoleColor(YELLOW);
  std::cout << functions.size();
  ResetConsoleColor();
  std::cout << " API functions\n";

  bool success = true;

  if (!struct_header_file.empty()) {
    success &= SaveToStructHeader(functions, struct_header_file);
  }

  if (!define_header_file.empty()) {
    success &= SaveToDefineHeader(functions, define_header_file);
  }

  if (success) {
    SetConsoleColor(GREEN);
    std::cout << "\n[+]\tAll operations completed\n";
    ResetConsoleColor();
    return 0;
  } else {
    SetConsoleColor(RED);
    std::cout <<
        "\n[!]\tSome operations failed. Check the output for details.\n";
    ResetConsoleColor();
    return 1;
  }
}