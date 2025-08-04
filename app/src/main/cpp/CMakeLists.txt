# Copyright 2025 Dakkshesh <beakthoven@gmail.com>
# SPDX-License-Identifier: GPL-3.0-or-later
cmake_minimum_required(VERSION 3.28)
project(TrickyStoreOSS)

find_package(cxx REQUIRED CONFIG)
link_libraries(cxx::cxx)

add_library(my_logging STATIC logging/logging.cpp)
target_include_directories(my_logging PUBLIC logging/include)
target_link_libraries(my_logging log)

set(LSPLT_SOURCES external/LSPlt/lsplt/src/main/jni/lsplt.cc external/LSPlt/lsplt/src/main/jni/elf_util.cc)
add_library(lsplt STATIC ${LSPLT_SOURCES})
target_include_directories(lsplt PUBLIC external/LSPlt/lsplt/src/main/jni/include)
target_include_directories(lsplt PRIVATE external/LSPlt/lsplt/src/main/jni)
target_link_libraries(lsplt PUBLIC my_logging)

# libutils stub
add_library(utils SHARED stub/stub_utils.cpp)
target_include_directories(utils PUBLIC external/AOSP/include)

# libbinder stub
add_library(binder SHARED stub/stub_binder.cpp)
target_include_directories(binder PUBLIC external/AOSP/include)
target_link_libraries(binder PRIVATE utils)

add_executable(libinject.so inject/main.cpp inject/utils.cpp)
target_link_libraries(libinject.so PRIVATE lsplt my_logging)

add_library(${CMAKE_PROJECT_NAME} SHARED binder_interceptor.cpp)
target_include_directories(${CMAKE_PROJECT_NAME} PUBLIC external/linux-kernel/include)
target_link_libraries(${CMAKE_PROJECT_NAME} PRIVATE log binder utils lsplt my_logging)
