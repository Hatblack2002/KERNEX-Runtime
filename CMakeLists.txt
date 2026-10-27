cmake_minimum_required(VERSION 3.20)
project(KERNEXRuntime VERSION 0.1.0 LANGUAGES CXX)

include(CTest)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(kernex_common INTERFACE)
target_include_directories(kernex_common INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/src)

add_executable(kernex_envprobe src/common/envprobe.cpp)
target_link_libraries(kernex_envprobe PRIVATE kernex_common)

add_executable(kernex_peinfo tools/peinfo.cpp)
target_link_libraries(kernex_peinfo PRIVATE kernex_common)

if(BUILD_TESTING)
  add_executable(kernex_smoke_test tests/smoke.cpp)
  target_link_libraries(kernex_smoke_test PRIVATE kernex_common)
  add_test(NAME smoke COMMAND kernex_smoke_test)

  add_executable(kernex_pe_parser_test tests/pe_parser_test.cpp)
  target_link_libraries(kernex_pe_parser_test PRIVATE kernex_common)
  add_test(NAME pe_parser COMMAND kernex_pe_parser_test)

  add_executable(kernex_pe_parser_stress_test tests/pe_parser_stress_test.cpp)
  target_link_libraries(kernex_pe_parser_stress_test PRIVATE kernex_common)
  add_test(NAME pe_parser_stress COMMAND kernex_pe_parser_stress_test)

  add_executable(kernex_x86_decode_test tests/x86_decode_test.cpp)
  target_link_libraries(kernex_x86_decode_test PRIVATE kernex_common)
  add_test(NAME x86_decode COMMAND kernex_x86_decode_test)

  add_executable(kernex_x86_decode_stress_test tests/x86_decode_stress_test.cpp)
  target_link_libraries(kernex_x86_decode_stress_test PRIVATE kernex_common)
  add_test(NAME x86_decode_stress COMMAND kernex_x86_decode_stress_test)

  add_executable(kernex_x86_cpu32_test tests/x86_cpu32_test.cpp)
  target_link_libraries(kernex_x86_cpu32_test PRIVATE kernex_common)
  add_test(NAME x86_cpu32 COMMAND kernex_x86_cpu32_test)

  add_executable(kernex_pe_import_symbols_test tests/pe_import_symbols_test.cpp)
  target_link_libraries(kernex_pe_import_symbols_test PRIVATE kernex_common)
  add_test(NAME pe_import_symbols COMMAND kernex_pe_import_symbols_test)
endif()
