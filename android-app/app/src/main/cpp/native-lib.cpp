#include <jni.h>
#include <cstdint>
#include <sstream>
#include <string>
#include <vector>
#include "pe/pe_image.hpp"
#include "pe/load_image.hpp"
#include "runtime/execute_pe32.hpp"

namespace {
std::vector<std::uint8_t> copy_bytes(JNIEnv* env, jbyteArray input) {
  const jsize size = env->GetArrayLength(input);
  std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size));
  if (size) env->GetByteArrayRegion(input, 0, size, reinterpret_cast<jbyte*>(bytes.data()));
  return bytes;
}
jstring to_java(JNIEnv* env, const std::string& text) {
  return env->NewStringUTF(text.c_str());
}
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_kernex_runtime_MainActivity_nativeStatus(JNIEnv* env, jobject) {
  return to_java(env,
      "Native ARM64 library loaded successfully.\n"
      "Status: experimental build; no Windows API compatibility layer.\n"
      "Select a PE file to inspect its headers. Inspection is not proof that it can run.");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_kernex_runtime_MainActivity_inspectPe(JNIEnv* env, jobject, jbyteArray input) {
  if (input == nullptr) return to_java(env, "No file data received.");
  try {
    const auto bytes = copy_bytes(env, input);
    const auto parsed = kernex::pe::parse(bytes);
    if (!parsed.ok) return to_java(env, std::string("Invalid or unsupported PE file:\n") + parsed.error);
    const auto& image = parsed.image;
    std::ostringstream out;
    out << "PE file parsed successfully\n"
        << "Architecture: " << (image.is_pe32_plus ? "PE32+ (64-bit)" : "PE32 (32-bit)") << "\n"
        << "Machine: 0x" << std::hex << image.machine << std::dec << "\n"
        << "Sections: " << image.section_count << "\n"
        << "Entry point RVA: 0x" << std::hex << image.entry_point << std::dec << "\n"
        << "Preferred image base: 0x" << std::hex << image.image_base << std::dec << "\n"
        << "Image size: " << image.size_of_image << " bytes\n"
        << "Imports directory: RVA 0x" << std::hex << image.import_directory_rva
        << ", size 0x" << image.import_directory_size << std::dec << "\n\n"
        << "Execution status: NOT ATTEMPTED.\n"
        << "The interpreter supports only a small x86-32 instruction subset and does not yet "
           "implement Windows process initialization, DLL/API emulation, TLS, or graphics.";
    return to_java(env, out.str());
  } catch (const std::exception& e) {
    return to_java(env, std::string("PE inspection failed safely: ") + e.what());
  } catch (...) {
    return to_java(env, "PE inspection failed with an unknown native error.");
  }
}
