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

if(BUILD_TESTING)
  add_executable(kernex_smoke_test tests/smoke.cpp)
  target_link_libraries(kernex_smoke_test PRIVATE kernex_common)
  add_test(NAME smoke COMMAND kernex_smoke_test)
endif()