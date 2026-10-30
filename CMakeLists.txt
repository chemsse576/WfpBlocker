cmake_minimum_required(VERSION 3.16)
project(WfpBlocker LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "WfpBlocker requires x64 build. Use -A x64")
endif()

set(SOURCES
    src/main.cpp
    src/wfp.cpp
    src/enumproc.cpp
    src/token.cpp
    src/convert.cpp
    src/edrlist.cpp
)

set(HEADERS
    src/commun.h
    src/wfp.h
    src/enumproc.h
    src/token.h
    src/convert.h
    src/edrlist.h
)

add_executable(WfpBlocker ${SOURCES} ${HEADERS})

set_property(TARGET WfpBlocker PROPERTY
    MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

target_compile_options(WfpBlocker PRIVATE /W3 /O2 /utf-8)

target_compile_definitions(WfpBlocker PRIVATE
    _CRT_SECURE_NO_WARNINGS
    UNICODE
    _UNICODE
)

target_link_options(WfpBlocker PRIVATE /SUBSYSTEM:CONSOLE)

target_link_libraries(WfpBlocker PRIVATE fwpuclnt)
