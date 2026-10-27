#include "pe/pe_image.hpp"

#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

static std::string safe_section_name(const std::string& name) {
  std::string out;
  out.reserve(name.size());
  for (unsigned char c : name) {
    // Keep JSON valid even for malformed/non-printable section names.
    if (c >= 0x20 && c <= 0x7e && c != '"' && c != '\\') out.push_back(static_cast<char>(c));
    else out.push_back('_');
  }
  return out;
}

static const char* machine_name(std::uint16_t machine) {
  switch (machine) {
    case 0x014c: return "x86";
    case 0x8664: return "x86_64";
    case 0x01c0: return "arm";
    case 0xaa64: return "arm64";
    default: return "unknown";
  }
}

int main(int argc, char** argv) {
  if (argc != 2) {
    std::cerr << "usage: peinfo <file.exe-or-dll>\n";
    return 2;
  }
  std::ifstream file(argv[1], std::ios::binary);
  if (!file) {
    std::cerr << "peinfo: cannot open input file\n";
    return 2;
  }
  std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(file)), {});
  const auto parsed = kernex::pe::parse(bytes);
  if (!parsed.ok) {
    std::cerr << "peinfo: invalid or unsupported PE: " << parsed.error << "\n";
    return 1;
  }
  const auto& p = parsed.image;
  std::cout << "{\n"
            << "  \"format\": \"PE\",\n"
            << "  \"machine\": \"" << machine_name(p.machine) << "\",\n"
            << "  \"machine_value\": " << p.machine << ",\n"
            << "  \"kind\": \"" << (p.is_pe32_plus ? "PE32+" : "PE32") << "\",\n"
            << "  \"entry_point_rva\": " << p.entry_point << ",\n"
            << "  \"image_base\": " << p.image_base << ",\n"
            << "  \"section_alignment\": " << p.section_alignment << ",\n"
            << "  \"file_alignment\": " << p.file_alignment << ",\n"
            << "  \"size_of_image\": " << p.size_of_image << ",\n"
            << "  \"size_of_headers\": " << p.size_of_headers << ",\n"
            << "  \"directories\": {\n"
            << "    \"imports\": {\"rva\": " << p.import_directory_rva << ", \"size\": " << p.import_directory_size << "},\n"
            << "    \"base_relocations\": {\"rva\": " << p.base_relocation_directory_rva << ", \"size\": " << p.base_relocation_directory_size << "},\n"
            << "    \"tls\": {\"rva\": " << p.tls_directory_rva << ", \"size\": " << p.tls_directory_size << "},\n"
            << "    \"delay_imports\": {\"rva\": " << p.delay_import_directory_rva << ", \"size\": " << p.delay_import_directory_size << "}\n"
            << "  },\n"
            << "  \"sections\": [";
  for (std::size_t i = 0; i < p.sections.size(); ++i) {
    const auto& s = p.sections[i];
    if (i) std::cout << ",";
    std::cout << "\n    {\"name\": \"" << safe_section_name(s.name)
              << "\", \"virtual_size\": " << s.virtual_size
              << ", \"virtual_address\": " << s.virtual_address
              << ", \"raw_size\": " << s.raw_size
              << ", \"raw_offset\": " << s.raw_offset
              << ", \"characteristics\": " << s.characteristics << "}";
  }
  if (!p.sections.empty()) std::cout << "\n  ";
  std::cout << "]\n}\n";
  return 0;
}