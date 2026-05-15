cmake_minimum_required(VERSION 3.20)
project(snooptop VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

include(FetchContent)
FetchContent_Declare(
  ftxui
  GIT_REPOSITORY https://github.com/ArthurSonzogni/FTXUI
  GIT_TAG main
)
FetchContent_MakeAvailable(ftxui)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/snooptop.skel.h
    COMMAND clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c ${CMAKE_SOURCE_DIR}/src/bpf/snooptop.bpf.c -o ${CMAKE_CURRENT_BINARY_DIR}/snooptop.bpf.o
    COMMAND bpftool gen skeleton ${CMAKE_CURRENT_BINARY_DIR}/snooptop.bpf.o > ${CMAKE_CURRENT_BINARY_DIR}/snooptop.skel.h
    DEPENDS ${CMAKE_SOURCE_DIR}/src/bpf/snooptop.bpf.c
)

include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_SOURCE_DIR}/src
    ${LIBBPF_INCLUDE_DIRS}
)

add_executable(snooptop
    src/main.cpp
    src/backend/bpf_engine.cpp
    ${CMAKE_CURRENT_BINARY_DIR}/snooptop.skel.h
)

target_link_libraries(snooptop
    PRIVATE
    ${LIBBPF_LIBRARIES}
    ftxui::screen
    ftxui::dom
    ftxui::component
)
