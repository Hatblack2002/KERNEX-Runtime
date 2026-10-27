#include <iostream>
#include <string>

#if defined(__aarch64__)
static constexpr const char* kArch = "aarch64";
#elif defined(__x86_64__) || defined(_M_X64)
static constexpr const char* kArch = "x86_64";
#elif defined(__i386__) || defined(_M_IX86)
static constexpr const char* kArch = "x86";
#else
static constexpr const char* kArch = "unknown";
#endif

#if defined(__clang__)
static constexpr const char* kCompiler = "clang";
#elif defined(__GNUC__)
static constexpr const char* kCompiler = "gcc";
#elif defined(_MSC_VER)
static constexpr const char* kCompiler = "msvc";
#else
static constexpr const char* kCompiler = "unknown";
#endif

int main() {
  // This is a build-environment probe, not a runtime hardware probe.
  std::cout << "{\n"
            << "  \"schema_version\": 1,\n"
            << "  \"project\": \"KERNEX-Runtime\",\n"
            << "  \"status\": \"scaffold\",\n"
            << "  \"compiled_arch\": \"" << kArch << "\",\n"
            << "  \"compiler\": \"" << kCompiler << "\",\n"
            << "  \"cplusplus\": " << __cplusplus << "\n"
            << "}\n";
  return 0;
}